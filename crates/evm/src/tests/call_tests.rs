use std::str::FromStr;

use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::{address, Address, BlockNumberOrTag, Bytes, TxKind, U64};
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::evm::DbAccount;
use crate::handler::L1_FEE_OVERHEAD;
use crate::smart_contracts::{
    BlockHashContract, InfiniteLoopContract, LogsContract, SelfDestructorContract,
    SimpleStorageContract, TestContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::get_evm;
use crate::tests::DEFAULT_CHAIN_ID;
use crate::{
    AccountData, EvmConfig, RlpEvmTransaction, BASE_FEE_VAULT, L1_FEE_VAULT, PRIORITY_FEE_VAULT,
};

type C = DefaultContext;

#[test]
fn call_multiple_test() {
    let dev_signer1: TestSigner = TestSigner::new_random();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer1.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        // SHANGAI instead of LATEST
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (mut evm, mut working_set) = get_evm(&config);

    let contract_addr = address!("819c5497b157177315e1204f52e588b393771719");

    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");

        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer1, 0, SimpleStorageContract::default()),
            set_arg_transaction(contract_addr, &dev_signer1, 1, set_arg + 1),
            set_arg_transaction(contract_addr, &dev_signer1, 2, set_arg + 2),
            set_arg_transaction(contract_addr, &dev_signer1, 3, set_arg + 3),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let account_info = evm.accounts.get(&contract_addr, &working_set).unwrap();

    // Make sure the contract db account size is 75 bytes
    let db_account_len = bcs::to_bytes(&account_info)
        .expect("Failed to serialize value")
        .len();
    assert_eq!(db_account_len, 75);

    let eoa_account_info = evm
        .accounts
        .get(&dev_signer1.address(), &working_set)
        .unwrap();
    // Make sure the eoa db account size is 42 bytes
    let db_account_len = bcs::to_bytes(&eoa_account_info)
        .expect("Failed to serialize value")
        .len();
    assert_eq!(db_account_len, 42);
    let db_account = DbAccount::new(contract_addr);
    let storage_value = db_account.storage.get(&U256::ZERO, &working_set).unwrap();

    assert_eq!(U256::from(set_arg + 3), storage_value);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![],
                },
                gas_used: 132943,
                log_index_start: 0,
                l1_diff_size: 567,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![],
                },
                gas_used: 43730,
                log_index_start: 0,
                l1_diff_size: 255,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 203303,
                    logs: vec![],
                },
                gas_used: 26630,
                log_index_start: 0,
                l1_diff_size: 255,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 229933,
                    logs: vec![],
                },
                gas_used: 26630,
                log_index_start: 0,
                l1_diff_size: 255,
            }
        ]
    );

    // checkout esad/fix-block-env-bug branch
    let tx = evm
        .get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(l2_height),
            U64::from(0),
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    assert_eq!(tx.block_number.unwrap(), l2_height);
}

#[test]
fn call_test() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        let rlp_transactions = vec![
            create_contract_message(&dev_signer, 0, SimpleStorageContract::default()),
            set_arg_message(contract_addr, &dev_signer, 1, set_arg),
        ];

        let call_message = CallMessage {
            txs: rlp_transactions,
        };

        evm.call(call_message, &context, &mut working_set).unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let db_account = DbAccount::new(contract_addr);
    let storage_value = db_account.storage.get(&U256::ZERO, &working_set).unwrap();

    assert_eq!(U256::from(set_arg), storage_value);
    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![],
                },
                gas_used: 132943,
                log_index_start: 0,
                l1_diff_size: 567,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![],
                },
                gas_used: 43730,
                log_index_start: 0,
                l1_diff_size: 255,
            }
        ]
    )
}

#[test]
fn failed_transaction_test() {
    let dev_signer: TestSigner = TestSigner::new_random();
    let (mut evm, mut working_set) = get_evm(&EvmConfig::default());
    let working_set = &mut working_set;
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );
        let rlp_transactions = vec![create_contract_message(
            &dev_signer,
            0,
            SimpleStorageContract::default(),
        )];

        let call_message = CallMessage {
            txs: rlp_transactions,
        };
        evm.call(call_message, &context, working_set).unwrap();
    }

    // assert no pending transaction
    let pending_txs = &evm.pending_transactions;
    assert_eq!(pending_txs.len(), 0);

    evm.end_soft_confirmation_hook(&soft_confirmation_info, working_set);

    // assert no pending transaction
    let pending_txs = &evm.pending_transactions;
    assert_eq!(pending_txs.len(), 0);

    // Assert block does not have any transaction
    let block = evm.blocks.last(&mut working_set.accessory_state()).unwrap();
    assert_eq!(block.transactions.start, 0);
    assert_eq!(block.transactions.end, 0);
}

#[test]
fn self_destruct_test() {
    let contract_balance: u64 = 1000000000000000;

    // address used in selfdestruct
    let die_to_address = address!("11115497b157177315e1204f52e588b393111111");

    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);
    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        // deploy selfdestruct contract
        // send some money to the selfdestruct contract
        // set some variable in the contract
        let rlp_transactions = vec![
            create_contract_message(&dev_signer, 0, SelfDestructorContract::default()),
            send_money_to_contract_message(contract_addr, &dev_signer, 1, contract_balance as u128),
            set_selfdestruct_arg_message(contract_addr, &dev_signer, 2, 123),
        ];

        evm.call(
            CallMessage {
                txs: rlp_transactions,
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    let contract_info = evm
        .accounts
        .get(&contract_addr, &working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to ocntract
    assert_eq!(contract_info.balance, U256::from(contract_balance));

    let db_contract = DbAccount::new(contract_addr);

    // Test if we managed to set the variable in the contract
    assert_eq!(
        db_contract
            .storage
            .get(&U256::from(0), &working_set)
            .unwrap(),
        U256::from(123)
    );

    // Test if the key is set in the keys statevec
    assert_eq!(db_contract.keys.len(&mut working_set), 1);
    let l1_fee_rate = 0;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 2,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [99u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );
        // selfdestruct
        evm.call(
            CallMessage {
                txs: vec![selfdestruct_message(
                    contract_addr,
                    &dev_signer,
                    3,
                    die_to_address,
                )],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    // we now delete destructed accounts from storage
    assert_eq!(evm.accounts.get(&contract_addr, &working_set), None);

    let die_to_acc = evm
        .accounts
        .get(&die_to_address, &working_set)
        .expect("die to address should exist");

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert!(receipts[0].receipt.success);

    // the to address balance should be equal to contract balance
    assert_eq!(die_to_acc.balance, U256::from(contract_balance));

    let db_account = DbAccount::new(contract_addr);

    // the storage should be empty
    assert_eq!(db_account.storage.get(&U256::from(0), &working_set), None);

    // the keys should be empty
    assert_eq!(db_account.keys.len(&mut working_set), 0);
}

#[test]
fn test_block_hash_in_evm() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        let deploy_message = create_contract_message(&dev_signer, 0, BlockHashContract::default());

        evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    for _i in 0..514 {
        // generate 514 more blocks
        let l1_fee_rate = 0;
        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height,
            da_slot_hash: [5u8; 32],
            da_slot_height: 1,
            da_slot_txs_commitment: [42u8; 32],
            pre_state_root: [99u8; 32].to_vec(),
            current_spec: SovSpecId::Genesis,
            pub_key: vec![],
            deposit_data: vec![],
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

        l2_height += 1;
    }

    let _last_block_number = evm
        .blocks
        .last(&mut working_set.accessory_state())
        .unwrap()
        .header
        .number;

    let _block_number = _last_block_number;

    let mut request = TransactionRequest {
        from: None,
        to: Some(TxKind::Call(contract_addr)),
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        gas: None,
        input: TransactionInput {
            data: None,
            input: Some(BlockHashContract::default().get_block_hash(0).into()),
        },
        nonce: Some(0u64),
        chain_id: Some(DEFAULT_CHAIN_ID),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
    };

    for i in 0..=1000 {
        request.input.input = Some(BlockHashContract::default().get_block_hash(i).into());
        let resp = evm.get_call(request.clone(), None, None, None, &mut working_set);
        if !(260..=515).contains(&i) {
            // Should be 0, there is more than 256 blocks between the last block and the block number
            assert_eq!(resp.unwrap().to_vec(), vec![0u8; 32]);
        } else {
            // Should be equal to the hash in accessory state
            let block = evm
                .blocks
                .get((i) as usize, &mut working_set.accessory_state());
            assert_eq!(
                resp.unwrap().to_vec(),
                block.unwrap().header.hash().to_vec()
            );
        }
    }
}

#[test]
fn test_block_gas_limit() {
    let (config, dev_signer, contract_addr) = get_evm_config(
        U256::from_str("100000000000000000000").unwrap(),
        Some(ETHEREUM_BLOCK_GAS_LIMIT),
    );

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        // deploy logs contract
        let mut rlp_transactions = vec![create_contract_message(
            &dev_signer,
            0,
            LogsContract::default(),
        )];

        for i in 0..10_000 {
            rlp_transactions.push(publish_event_message(
                contract_addr,
                &dev_signer,
                i + 1,
                "hello".to_string(),
            ));
        }

        evm.call(
            CallMessage {
                txs: rlp_transactions,
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let block = evm
        .get_block_by_number(Some(BlockNumberOrTag::Latest), None, &mut working_set)
        .unwrap()
        .unwrap();

    assert_eq!(block.header.gas_limit, ETHEREUM_BLOCK_GAS_LIMIT as _);
    assert!(block.header.gas_used <= block.header.gas_limit);
    assert!(
        block.transactions.hashes().len() < 10_000,
        "Some transactions should be dropped because of gas limit"
    );
}

pub fn create_contract_message<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction(TxKind::Create, contract.byte_code(), nonce, 0)
        .unwrap()
}

pub(crate) fn create_contract_message_with_fee<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
    max_fee_per_gas: u128,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction_with_fee(
            TxKind::Create,
            contract.byte_code(),
            nonce,
            0,
            max_fee_per_gas,
        )
        .unwrap()
}

pub(crate) fn create_contract_message_with_priority_fee<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction_with_priority_fee(
            TxKind::Create,
            contract.byte_code(),
            nonce,
            0,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        )
        .unwrap()
}

pub(crate) fn create_contract_transaction<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> RlpEvmTransaction {
    dev_signer
        .sign_default_transaction(TxKind::Create, contract.byte_code(), nonce, 0)
        .unwrap()
}

fn set_selfdestruct_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> RlpEvmTransaction {
    let contract = SimpleStorageContract::default();

    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.set_call_data(set_arg),
            nonce,
            0,
        )
        .unwrap()
}

pub(crate) fn set_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> RlpEvmTransaction {
    let contract = SimpleStorageContract::default();

    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.set_call_data(set_arg),
            nonce,
            0,
        )
        .unwrap()
}

fn set_arg_transaction(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> RlpEvmTransaction {
    let contract = SimpleStorageContract::default();

    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.set_call_data(set_arg),
            nonce,
            0,
        )
        .unwrap()
}

fn send_money_to_contract_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    value: u128,
) -> RlpEvmTransaction {
    signer
        .sign_default_transaction(TxKind::Call(contract_addr), vec![], nonce, value)
        .unwrap()
}

fn selfdestruct_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    to_address: Address,
) -> RlpEvmTransaction {
    let contract = SelfDestructorContract::default();

    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.selfdestruct(to_address),
            nonce,
            0,
        )
        .unwrap()
}

pub(crate) fn publish_event_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    message: String,
) -> RlpEvmTransaction {
    let contract = LogsContract::default();

    signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.publish_event(message),
            nonce,
            0,
        )
        .unwrap()
}

pub(crate) fn get_evm_config(
    signer_balance: U256,
    block_gas_limit: Option<u64>,
) -> (EvmConfig, TestSigner, Address) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr = address!("819c5497b157177315e1204f52e588b393771719");
    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: signer_balance,
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        block_gas_limit: block_gas_limit.unwrap_or(ETHEREUM_BLOCK_GAS_LIMIT),
        ..Default::default()
    };
    (config, dev_signer, contract_addr)
}

pub(crate) fn get_evm_config_starting_base_fee(
    signer_balance: U256,
    block_gas_limit: Option<u64>,
    starting_base_fee: u64,
) -> (EvmConfig, TestSigner, Address) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr = address!("819c5497b157177315e1204f52e588b393771719");
    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: signer_balance,
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        block_gas_limit: block_gas_limit.unwrap_or(ETHEREUM_BLOCK_GAS_LIMIT),
        starting_base_fee,
        coinbase: PRIORITY_FEE_VAULT,
        ..Default::default()
    };
    (config, dev_signer, contract_addr)
}

#[test]
fn test_l1_fee_success() {
    fn run_tx(
        l1_fee_rate: u128,
        expected_balance: U256,
        expected_coinbase_balance: U256,
        expected_base_fee_vault_balance: U256,
        expected_l1_fee_vault_balance: U256,
    ) {
        let (config, dev_signer, _) =
            get_evm_config_starting_base_fee(U256::from_str("100000000000000").unwrap(), None, 1);

        let (mut evm, mut working_set) = get_evm(&config);

        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height: 2,
            da_slot_hash: [5u8; 32],
            da_slot_height: 1,
            da_slot_txs_commitment: [42u8; 32],
            pre_state_root: [10u8; 32].to_vec(),
            current_spec: SovSpecId::Genesis,
            pub_key: vec![],
            deposit_data: vec![],
            l1_fee_rate,
            timestamp: 0,
        };

        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        {
            let sender_address = generate_address::<C>("sender");
            let sequencer_address = generate_address::<C>("sequencer");
            let context = C::new(
                sender_address,
                sequencer_address,
                2,
                SovSpecId::Genesis,
                l1_fee_rate,
            );

            let deploy_message = create_contract_message_with_priority_fee(
                &dev_signer,
                0,
                BlockHashContract::default(),
                20000000, // 2 gwei
                1,
            );

            evm.call(
                CallMessage {
                    txs: vec![deploy_message],
                },
                &context,
                &mut working_set,
            )
            .unwrap();
        }
        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

        let db_account = evm
            .accounts
            .get(&dev_signer.address(), &working_set)
            .unwrap();

        let base_fee_valut = evm.accounts.get(&BASE_FEE_VAULT, &working_set).unwrap();
        let l1_fee_valut = evm.accounts.get(&L1_FEE_VAULT, &working_set).unwrap();

        let coinbase_account = evm.accounts.get(&config.coinbase, &working_set).unwrap();
        assert_eq!(config.coinbase, PRIORITY_FEE_VAULT);

        assert_eq!(db_account.balance, expected_balance);
        assert_eq!(base_fee_valut.balance, expected_base_fee_vault_balance);
        assert_eq!(coinbase_account.balance, expected_coinbase_balance);
        assert_eq!(l1_fee_valut.balance, expected_l1_fee_vault_balance);

        assert_eq!(
            evm.receipts
                .iter(&mut working_set.accessory_state())
                .collect::<Vec<_>>(),
            [Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 114235,
                    logs: vec![],
                },
                gas_used: 114235,
                log_index_start: 0,
                l1_diff_size: 479,
            },]
        )
    }

    let gas_fee_paid = 114235;

    run_tx(
        0,
        U256::from(100000000000000u64 - gas_fee_paid * 10000001),
        // priority fee goes to coinbase
        U256::from(gas_fee_paid),
        U256::from(gas_fee_paid * 10000000),
        U256::from(0),
    );
    run_tx(
        1,
        U256::from(100000000000000u64 - gas_fee_paid * 10000001 - 479 - L1_FEE_OVERHEAD as u64),
        // priority fee goes to coinbase
        U256::from(gas_fee_paid),
        U256::from(gas_fee_paid * 10000000),
        U256::from(479 + L1_FEE_OVERHEAD as u64),
    );
}

#[test]
fn test_l1_fee_not_enough_funds() {
    let (config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

    let l1_fee_rate = 10000;
    let (mut evm, mut working_set) = get_evm(&config);

    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        let deploy_message =
            create_contract_message_with_fee(&dev_signer, 0, BlockHashContract::default(), 1);

        let call_result = evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        );

        assert!(call_result.is_ok());

        let block = evm.blocks.last(&mut working_set.accessory_state()).unwrap();
        assert!(block.transactions.is_empty());
    }

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let db_account = evm
        .accounts
        .get(&dev_signer.address(), &working_set)
        .unwrap();

    // The account balance is unchanged
    assert_eq!(db_account.balance, U256::from(1000000));
    assert_eq!(db_account.nonce, 0);

    // The coinbase was not created
    let db_coinbase = evm.accounts.get(&config.coinbase, &working_set);
    assert!(db_coinbase.is_none());
}

#[test]
fn test_l1_fee_halt() {
    let (config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("20000000000000").unwrap(), None, 1);

    let (mut evm, mut working_set) = get_evm(&config); // l2 height 1
    let l1_fee_rate = 1;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SovSpecId::Genesis,
            l1_fee_rate,
        );

        let deploy_message = create_contract_message_with_fee(
            &dev_signer,
            0,
            InfiniteLoopContract::default(),
            10000000,
        );

        let call_message = dev_signer
            .sign_default_transaction_with_fee(
                TxKind::Call(address!("819c5497b157177315e1204f52e588b393771719")),
                InfiniteLoopContract::default()
                    .call_infinite_loop()
                    .into_iter()
                    .collect(),
                1,
                0,
                10000000,
            )
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_message, call_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 106947,
                    logs: vec![],
                },
                gas_used: 106947,
                log_index_start: 0,
                l1_diff_size: 447,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: false,
                    cumulative_gas_used: 1106947,
                    logs: vec![],
                },
                gas_used: 1000000,
                log_index_start: 0,
                l1_diff_size: 96,
            },
        ]
    );

    let db_account = evm
        .accounts
        .get(&dev_signer.address(), &working_set)
        .unwrap();

    let expenses = 1106947_u64 * 10000000 + // evm gas
        447  + // l1 contract deploy fee
        96  + // l1 contract call fee
        2 * L1_FEE_OVERHEAD as u64; // l1 fee overhead *2
    assert_eq!(
        db_account.balance,
        U256::from(
            20000000000000_u64 - // initial balance
            expenses
        )
    );

    let base_fee_valut = evm.accounts.get(&BASE_FEE_VAULT, &working_set).unwrap();
    let l1_fee_valut = evm.accounts.get(&L1_FEE_VAULT, &working_set).unwrap();

    assert_eq!(base_fee_valut.balance, U256::from(1106947_u64 * 10000000));
    assert_eq!(
        l1_fee_valut.balance,
        U256::from(447 + 96 + 2 * L1_FEE_OVERHEAD as u64)
    );
}
