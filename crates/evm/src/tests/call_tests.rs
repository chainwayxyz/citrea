use std::str::FromStr;

use alloy::hex::FromHex;
use alloy_consensus::TxReceipt;
use alloy_eips::eip1559::ETHEREUM_BLOCK_GAS_LIMIT_30M;
use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{address, Address, Bytes, TxKind, B256, U64};
use alloy_rpc_types::{TransactionInput, TransactionRequest};
use citrea_primitives::min_base_fee_per_gas;
use rand::thread_rng;
use revm::bytecode::eip7702::Eip7702Bytecode;
use revm::primitives::{KECCAK_EMPTY, U256};
use revm::state::Bytecode;
use revm::Database;
use secp256k1::SecretKey;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{
    Context, L2BlockModuleCallError, Module, StateMapAccessor, StateVecAccessor,
};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::primitive_types::CitreaReceiptWithBloom;
use crate::handler::{BROTLI_COMPRESSION_PERCENTAGE, L1_FEE_OVERHEAD};
use crate::smart_contracts::{
    BlockHashContract, InfiniteLoopContract, LogsContract, SelfDestructorContract,
    SimpleStorageContract, TestContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    config_push_contracts, create_contract_message, create_contract_message_with_fee,
    create_contract_message_with_fee_and_gas_limit, create_contract_transaction, get_evm,
    get_evm_config, get_evm_config_starting_base_fee, get_evm_with_spec, get_fork_fn_latest,
    publish_event_message, set_arg_message,
};
use crate::tests::{get_test_seq_pub_key, DEFAULT_CHAIN_ID};
use crate::{
    AccountData, EvmConfig, RlpEvmTransaction, BASE_FEE_VAULT, L1_FEE_VAULT, PRIORITY_FEE_VAULT,
};
type C = DefaultContext;

#[test]
fn call_multiple_test() {
    let dev_signer1: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer1.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };
    let (mut evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);

    let contract_addr = dev_signer1.address().create(0);

    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let account_info = evm.account_info(&contract_addr, &mut working_set).unwrap();

    // Make sure the contract db account size is 75 bytes
    let db_account_len = bcs::to_bytes(&account_info)
        .expect("Failed to serialize value")
        .len();
    assert_eq!(db_account_len, 75);

    let eoa_account_info = evm
        .account_info(&dev_signer1.address(), &mut working_set)
        .unwrap();
    // Make sure the eoa db account size is 42 bytes
    let db_account_len = bcs::to_bytes(&eoa_account_info)
        .expect("Failed to serialize value")
        .len();
    assert_eq!(db_account_len, 42);
    let storage_value = evm
        .storage_get(&contract_addr, &U256::ZERO, &mut working_set)
        .unwrap();
    assert_eq!(U256::from(set_arg + 3), storage_value);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![]
                }
                .into(),
                gas_used: 132943,
                log_index_start: 0,
                l1_diff_size: 38
            },
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![]
                }
                .into(),
                gas_used: 43730,
                log_index_start: 0,
                l1_diff_size: 30
            },
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 203303,
                    logs: vec![]
                }
                .into(),
                gas_used: 26630,
                log_index_start: 0,
                l1_diff_size: 30
            },
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 229933,
                    logs: vec![]
                }
                .into(),
                gas_used: 26630,
                log_index_start: 0,
                l1_diff_size: 30
            }
        ]
    );
    // checkout esad/fix-block-env-bug branch
    let tx = evm
        .get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(l2_height),
            U64::from(0),
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();

    assert_eq!(tx.block_number.unwrap(), l2_height);
}

#[test]
fn call_test() {
    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);
    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let contract_addr = dev_signer.address().create(0);

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let rlp_transactions = vec![
            create_contract_message(&dev_signer, 0, SimpleStorageContract::default()),
            set_arg_message(contract_addr, &dev_signer, 1, set_arg),
        ];

        let call_message = CallMessage {
            txs: rlp_transactions,
        };

        evm.call(call_message, &context, &mut working_set).unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let storage_value = evm
        .storage_get(&contract_addr, &U256::ZERO, &mut working_set)
        .unwrap();

    assert_eq!(U256::from(set_arg), storage_value);
    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![]
                }
                .into(),
                gas_used: 132943,
                log_index_start: 0,
                l1_diff_size: 38
            },
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![]
                }
                .into(),
                gas_used: 43730,
                log_index_start: 0,
                l1_diff_size: 30
            }
        ]
    );
}

#[test]
fn failed_transaction_test() {
    let dev_signer: TestSigner = TestSigner::new_default();
    let config = EvmConfig::default();

    let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);
    let working_set = &mut working_set;
    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);
        let rlp_transactions = vec![create_contract_message(
            &dev_signer,
            0,
            SimpleStorageContract::default(),
        )];

        let call_message = CallMessage {
            txs: rlp_transactions,
        };

        assert_eq!(
            evm.call(call_message, &context, working_set).unwrap_err(),
            L2BlockModuleCallError::EvmTransactionExecutionError(
                "transaction validation error: lack of funds (0) for max fee (100000000000000000)"
                    .to_string()
            )
        );
    }

    let pending_txs = &evm.pending_transactions;
    assert_eq!(pending_txs.len(), 0);

    evm.end_l2_block_hook(&l2_block_info, working_set);
    // assert no pending transaction
    let pending_txs = &evm.pending_transactions;
    assert_eq!(pending_txs.len(), 0);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        []
    );
    let block = evm.blocks.last(&mut working_set.accessory_state()).unwrap();
    assert_eq!(block.transactions.start, 0);
    assert_eq!(block.transactions.end, 0);
}

// tests first part of https://eips.ethereum.org/EIPS/eip-6780
// test self destruct behaviour after cancun
#[test]
fn self_destruct_test() {
    let contract_balance: u64 = 1000000000000000;

    // address used in selfdestruct
    let die_to_address = address!("11115497b157177315e1204f52e588b393111111");

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let contract_addr = dev_signer.address().create(0);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

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
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let contract_info = evm
        .account_info(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to contract
    assert_eq!(contract_info.balance, U256::from(contract_balance));

    // Test if we managed to set the variable in the contract
    assert_eq!(
        evm.storage_get(&contract_addr, &U256::from(0), &mut working_set)
            .unwrap(),
        U256::from(123)
    );

    let l1_fee_rate = 0;

    let contract_code_hash_before_destruct = contract_info.code_hash.unwrap();
    let contract_code_before_destruct = evm
        .offchain_code
        .get(
            &contract_code_hash_before_destruct,
            &mut working_set.offchain_state(),
        )
        .unwrap();

    // Activate fork1
    // After cancun activated here SELFDESTRUCT will recover all funds to the target
    // but not delete the account, except when called in the same transaction as creation
    // In this case the contract does not have a selfdestruct in the same transaction as creation
    // https://eips.ethereum.org/EIPS/eip-6780
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    // Switch to another fork
    let _spec_id = SovSpecId::latest();
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);
        // selfdestruct to die to address with someone other than the creator of the contract
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
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert!(receipts[0].receipt.status());

    // after cancun the funds go but account is not destructed if if selfdestruct is not called in creation
    let contract_info = evm
        .account_info(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to contract
    assert_eq!(contract_info.nonce, 1);
    assert_eq!(
        contract_info.code_hash.unwrap(),
        contract_code_hash_before_destruct
    );

    let code = evm
        .offchain_code
        .get(
            &contract_code_hash_before_destruct,
            &mut working_set.offchain_state(),
        )
        .unwrap();
    assert_eq!(code, contract_code_before_destruct);

    // Test if we managed to send money to contract
    assert_eq!(contract_info.balance, U256::from(0));

    let die_to_contract = evm
        .account_info(&die_to_address, &mut working_set)
        .expect("die to address should exist");

    // the to address balance should be equal to double contract balance now that two selfdestructs have been called
    assert_eq!(die_to_contract.balance, U256::from(contract_balance));

    // the storage should not be empty
    assert_eq!(
        evm.storage_get(&contract_addr, &U256::from(0), &mut working_set,),
        Some(U256::from(123))
    );
}

#[test]
fn test_block_hash_in_evm() {
    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let contract_addr = dev_signer.address().create(0);
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

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
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    for _i in 0..514 {
        // generate 514 more blocks
        let l1_fee_rate = 0;
        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: [99u8; 32],
            current_spec: SovSpecId::latest(),
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };

        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

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
        authorization_list: None,
    };

    for i in 0..=1000 {
        request.input.input = Some(BlockHashContract::default().get_block_hash(i).into());
        let resp = evm.get_call_inner(
            request.clone(),
            None,
            None,
            None,
            &mut working_set,
            &ledger_db,
            get_fork_fn_latest(),
        );
        if (260..=515).contains(&i) {
            // Should be equal to the hash in accessory state
            let block = evm
                .blocks
                .get((i) as usize, &mut working_set.accessory_state());
            assert_eq!(
                resp.unwrap().to_vec(),
                block.unwrap().header.hash().to_vec()
            );
        } else {
            // Should be 0, there is more than 256 blocks between the last block and the block number
            assert_eq!(resp.unwrap().to_vec(), vec![0u8; 32]);
        }
    }

    // last produced block is 516, eth_call with pending should return latest block's hash
    let latest_block = evm.blocks.get(516, &mut working_set.accessory_state());
    request.input.input = Some(BlockHashContract::default().get_block_hash(516).into());

    let resp = evm.get_call_inner(
        request.clone(),
        Some(BlockId::pending()),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(
        resp.unwrap().to_vec(),
        latest_block.unwrap().header.hash().to_vec()
    );

    // but not 260's hash
    request.input.input = Some(BlockHashContract::default().get_block_hash(260).into());
    let resp = evm.get_call_inner(
        request.clone(),
        Some(BlockId::pending()),
        None,
        None,
        &mut working_set,
        &ledger_db,
        get_fork_fn_latest(),
    );

    assert_eq!(resp.unwrap().to_vec(), vec![0u8; 32]);
}

#[test]
fn test_block_gas_limit() {
    let (config, dev_signer) = get_evm_config(
        U256::from_str("100000000000000000000").unwrap(),
        Some(ETHEREUM_BLOCK_GAS_LIMIT_30M),
    );

    let contract_addr = dev_signer.address().create(0);

    let (mut evm, working_set, _spec_id, ledger_db) = get_evm(&config);

    let mut working_set = working_set.checkpoint().to_revertable();
    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        // deploy logs contract
        let mut rlp_transactions = vec![create_contract_message(
            &dev_signer,
            0,
            LogsContract::default(),
        )];

        // only 1129 of these transactions can be included in the block
        for i in 0..3_000 {
            rlp_transactions.push(publish_event_message(
                contract_addr,
                &dev_signer,
                i + 1,
                "hello".to_string(),
            ));
        }

        assert_eq!(
            evm.call(
                CallMessage {
                    txs: rlp_transactions.clone(),
                },
                &context,
                &mut working_set,
            )
            .unwrap_err(),
            L2BlockModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                cumulative_gas: 29997634,
                tx_gas_used: 26388,
                block_gas_limit: 30000000
            }
        );
    }

    // let's start over.

    let mut working_set = working_set.revert().to_revertable();

    assert_eq!(
        evm.get_db(&mut working_set, SovSpecId::latest())
            .basic(dev_signer.address())
            .unwrap()
            .unwrap()
            .nonce,
        0
    );

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        // deploy logs contract
        let mut rlp_transactions = vec![create_contract_message(
            &dev_signer,
            0,
            LogsContract::default(),
        )];

        // only 1136 of these transactions can be included in the block
        for i in 0..1129 {
            rlp_transactions.push(publish_event_message(
                contract_addr,
                &dev_signer,
                i + 1,
                "hello".to_string(),
            ));
        }

        let result = evm.call(
            CallMessage {
                txs: rlp_transactions.clone(),
            },
            &context,
            &mut working_set,
        );

        assert!(result.is_ok());
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();

    assert_eq!(block.header.gas_limit, ETHEREUM_BLOCK_GAS_LIMIT_30M);
    assert_eq!(block.header.gas_used, 29997634);
    assert_eq!(block.transactions.hashes().len(), 1130);
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

pub(crate) fn set_selfdestruct_arg_message(
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

pub(crate) fn send_money_to_contract_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    value: u128,
) -> RlpEvmTransaction {
    signer
        .sign_default_transaction(TxKind::Call(contract_addr), vec![], nonce, value)
        .unwrap()
}

pub(crate) fn selfdestruct_message(
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

#[test]
fn test_l1_fee_success() {
    fn run_tx(
        l1_fee_rate: u128,
        expected_balance: U256,
        expected_coinbase_balance: U256,
        expected_base_fee_vault_balance: U256,
        expected_l1_fee_vault_balance: U256,
    ) {
        let (mut config, dev_signer, _ledger_db) =
            get_evm_config_starting_base_fee(U256::from_str("100000000000000").unwrap(), None, 1);

        // this will push contracts to the config
        config_push_contracts(&mut config, None);

        let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

        let l2_block_info = HookL2BlockInfo {
            l2_height: 2,
            pre_state_root: [10u8; 32],
            current_spec: SovSpecId::latest(),
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };

        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
        {
            let sender_address = generate_address::<C>("sender");

            let context = C::new(sender_address, 2, SovSpecId::latest(), l1_fee_rate);

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
        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

        let db_account = evm
            .account_info(&dev_signer.address(), &mut working_set)
            .unwrap();

        let base_fee_vault = evm.account_info(&BASE_FEE_VAULT, &mut working_set).unwrap();
        let l1_fee_vault = evm.account_info(&L1_FEE_VAULT, &mut working_set).unwrap();

        let coinbase_account = evm
            .account_info(&config.coinbase, &mut working_set)
            .unwrap();
        assert_eq!(config.coinbase, PRIORITY_FEE_VAULT);

        assert_eq!(db_account.balance, expected_balance);
        assert_eq!(base_fee_vault.balance, expected_base_fee_vault_balance);
        assert_eq!(coinbase_account.balance, expected_coinbase_balance);
        assert_eq!(l1_fee_vault.balance, expected_l1_fee_vault_balance);

        assert_eq!(
            evm.receipts
                .iter(&mut working_set.accessory_state())
                .collect::<Vec<_>>(),
            [CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 114235,
                    logs: vec![]
                }
                .into(),
                gas_used: 114235,
                log_index_start: 0,
                l1_diff_size: 36 + L1_FEE_OVERHEAD as u64
            }]
        );
    }

    let gas_fee_paid = 114235;

    run_tx(
        0,
        U256::from(100000000000000u64 - gas_fee_paid * 1000001),
        // priority fee goes to coinbase
        U256::from(gas_fee_paid),
        U256::from(gas_fee_paid * 1000000),
        U256::from(0),
    );
    run_tx(
        1,
        U256::from(100000000000000u64 - gas_fee_paid * 1000001 - 36 - L1_FEE_OVERHEAD as u64),
        // priority fee goes to coinbase
        U256::from(gas_fee_paid),
        U256::from(gas_fee_paid * 1000000),
        U256::from(36 + L1_FEE_OVERHEAD as u64),
    );
}

#[test]
fn test_l1_fee_not_enough_funds() {
    let (mut config, dev_signer, _ledger_db) = get_evm_config_starting_base_fee(
        U256::from_str("114235000000").unwrap(), // only covers base fee
        None,
        min_base_fee_per_gas(SovSpecId::latest()),
    );
    config_push_contracts(&mut config, None);

    let l1_fee_rate = 10000;
    let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_message = create_contract_message_with_fee_and_gas_limit(
            &dev_signer,
            0,
            BlockHashContract::default(),
            min_base_fee_per_gas(l2_block_info.current_spec),
            114235,
        );

        // 114235 gas used
        let call_result = evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        );

        assert_eq!(
            call_result.unwrap_err(),
            L2BlockModuleCallError::EvmNotEnoughFundsForL1Fee
        );

        assert!(evm
            .receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>()
            .is_empty());
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let db_account = evm
        .account_info(&dev_signer.address(), &mut working_set)
        .unwrap();

    // The account balance is unchanged
    assert_eq!(db_account.balance, U256::from(114235000000u64));
    assert_eq!(db_account.nonce, 0);

    // The coinbase balance is zero
    let db_coinbase = evm
        .account_info(&config.coinbase, &mut working_set)
        .unwrap();
    assert_eq!(db_coinbase.balance, U256::from(0));
}

#[test]
fn test_l1_fee_halt() {
    let (mut config, dev_signer, _ledger_db) =
        get_evm_config_starting_base_fee(U256::from_str("20000000000000").unwrap(), None, 1);

    config_push_contracts(&mut config, None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config); // l2 height 1
    let l1_fee_rate = 1;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_message = create_contract_message_with_fee(
            &dev_signer,
            0,
            InfiniteLoopContract::default(),
            10000000,
        );

        let call_message = dev_signer
            .sign_default_transaction_with_fee(
                TxKind::Call(dev_signer.address().create(0)),
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
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 106947,
                    logs: vec![]
                }
                .into(),
                gas_used: 106947,
                log_index_start: 0,
                l1_diff_size: 36 + L1_FEE_OVERHEAD as u64
            },
            CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: false,
                    cumulative_gas_used: 1106947,
                    logs: vec![]
                }
                .into(),
                gas_used: 1000000,
                log_index_start: 0,
                l1_diff_size: 7 + L1_FEE_OVERHEAD as u64
            }
        ]
    );
    let db_account = evm
        .account_info(&dev_signer.address(), &mut working_set)
        .unwrap();

    let expenses = 1106947_u64 * 1000000 + // evm gas
        36 + // l1 contract deploy fee
        7 + // l1 contract call fee
        2 * L1_FEE_OVERHEAD as u64; // l1 fee overhead *2
    assert_eq!(
        db_account.balance,
        U256::from(
            20000000000000_u64 - // initial balance
            expenses
        )
    );
    let base_fee_vault = evm.account_info(&BASE_FEE_VAULT, &mut working_set).unwrap();
    let l1_fee_vault = evm.account_info(&L1_FEE_VAULT, &mut working_set).unwrap();

    assert_eq!(base_fee_vault.balance, U256::from(1106947_u64 * 1000000));
    assert_eq!(
        l1_fee_vault.balance,
        U256::from(36 + 7 + 2 * L1_FEE_OVERHEAD as u64)
    );
}

#[test]
fn test_l1_fee_compression_discount() {
    let (mut config, dev_signer, _ledger_db) =
        get_evm_config_starting_base_fee(U256::from_str("100000000000000").unwrap(), None, 1);

    config_push_contracts(&mut config, None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());
    let l1_fee_rate = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height: 2,
        pre_state_root: [99u8; 32],
        current_spec: SovSpecId::latest(), // Compression discount is enabled
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 3, SovSpecId::latest(), l1_fee_rate);
        let simple_tx = dev_signer
            .sign_default_transaction_with_priority_fee(
                TxKind::Call(Address::random()),
                vec![],
                0,
                1000,
                20000000,
                1,
            )
            .unwrap();
        evm.call(
            CallMessage {
                txs: vec![simple_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[98u8; 32], &mut working_set.accessory_state());

    let db_account = evm
        .account_info(&dev_signer.address(), &mut working_set)
        .unwrap();
    let base_fee_vault = evm.account_info(&BASE_FEE_VAULT, &mut working_set).unwrap();
    let l1_fee_vault = evm.account_info(&L1_FEE_VAULT, &mut working_set).unwrap();

    let coinbase_account = evm
        .account_info(&config.coinbase, &mut working_set)
        .unwrap();

    // gas fee remains the same
    let tx2_diff_size = 31;

    let tx_gas = 21000;

    let expected_db_balance = U256::from(
        100000000000000u64 - 1000 - tx_gas * 1000001 - tx2_diff_size - L1_FEE_OVERHEAD as u64,
    );
    let expected_base_fee_vault_balance = U256::from(tx_gas * 1000000);
    let expected_coinbase_balance = U256::from(tx_gas);
    let expected_l1_fee_vault_balance = U256::from(tx2_diff_size + L1_FEE_OVERHEAD as u64);

    assert_eq!(db_account.balance, expected_db_balance);
    assert_eq!(base_fee_vault.balance, expected_base_fee_vault_balance);
    assert_eq!(coinbase_account.balance, expected_coinbase_balance);
    assert_eq!(l1_fee_vault.balance, expected_l1_fee_vault_balance);

    assert_eq!(
        // diff size in receipt is the compressed diff size + L1 fee overhead
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .map(|r| r.l1_diff_size)
            .collect::<Vec<_>>(),
        [tx2_diff_size + L1_FEE_OVERHEAD as u64]
    );

    assert_eq!(
        65 * (BROTLI_COMPRESSION_PERCENTAGE as u64) / 100,
        tx2_diff_size
    );
}

// TODO: test is not doing anything significant at the moment
// after the cancun upgrade related issues are solved come back
// and invoke point eval precompile
#[test]
fn test_blob_tx() {
    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);
    let (mut evm, mut working_set, _spec_id, _ledger_db) = get_evm(&config);

    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(), // won't be Tangerine at height 2 currently but we can trick the spec id
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let sender_address = generate_address::<C>("sender");
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let blob_message = dev_signer
            .sign_blob_transaction(Address::ZERO, vec![B256::random()], 0)
            .unwrap();

        assert_eq!(
            evm.call(
                CallMessage {
                    txs: vec![blob_message],
                },
                &context,
                &mut working_set,
            )
            .unwrap_err(),
            L2BlockModuleCallError::EvmTxTypeNotSupported("EIP-4844".to_string())
        );
    }
}

#[test]
fn test_eip7702_tx() {
    // two signers
    // create log contract and set arg contract
    // get authorization from signer 1 that delegates to log contract
    // signer 2 sends transaction to signer1's address and we see log contract is called
    // assert both addresses nonce went up
    // then we assert receipts
    // then signer 1 delegates to set arg contract
    // signer 2 sends transaction to signer1's address
    // we check for storage of signer1 and see it has changed now

    let signer1 = TestSigner::new_default();
    let signer2 = TestSigner::new(SecretKey::new(&mut thread_rng()));

    let config = EvmConfig {
        data: vec![
            AccountData {
                address: signer1.address(),
                balance: U256::from_str("100000000000000000000").unwrap(),
                code_hash: KECCAK_EMPTY,
                code: Bytes::default(),
                nonce: 0,
                storage: Default::default(),
            },
            AccountData {
                address: signer2.address(),
                balance: U256::from_str("100000000000000000000").unwrap(),
                code_hash: KECCAK_EMPTY,
                code: Bytes::default(),
                nonce: 0,
                storage: Default::default(),
            },
        ],
        ..Default::default()
    };
    let (mut evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);

    let log_contract_address = signer1.address().create(0);

    let set_arg_contract_address = signer1.address().create(1);

    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&signer1, 0, LogsContract::default()),
            create_contract_transaction(&signer1, 1, SimpleStorageContract::default()),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let signer1_account_info_pre_delegate = evm
        .account_info(&signer1.address(), &mut working_set)
        .unwrap();

    assert_eq!(signer1_account_info_pre_delegate.nonce, 2);

    // signer1 delegates to log contract
    let auth = signer1
        .get_signed_authorization(log_contract_address, 2)
        .unwrap();

    // signer2 executes the transaction
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![signer2
            .sign_eip7702_transaction(
                signer1.address(),
                LogsContract::default().publish_event("helo".to_string()),
                0,
                vec![auth],
            )
            .unwrap()];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .last()
            .unwrap()
            .receipt
            .logs()
            .len(),
        2
    );

    let signer1_account_info_post_tx = evm
        .account_info(&signer1.address(), &mut working_set)
        .unwrap();

    assert_eq!(signer1_account_info_post_tx.nonce, 3);

    assert_eq!(
        signer1_account_info_post_tx.balance,
        signer1_account_info_pre_delegate.balance,
    );

    assert_eq!(
        evm.offchain_code.get(
            &signer1_account_info_post_tx.code_hash.unwrap(),
            &mut working_set.offchain_state()
        ),
        Some(Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: log_contract_address,
            version: 0,
            raw: [
                Bytes::from_hex("0xef0100").unwrap(),
                Bytes::from(log_contract_address.to_vec())
            ]
            .concat()
            .into()
        }))
    );

    // now let's see if we can call signer1 like it's log contract again
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![signer2
            .sign_default_transaction(
                TxKind::Call(signer1.address()),
                LogsContract::default().publish_event("helo".to_string()),
                1,
                0,
            )
            .unwrap()];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .last()
            .unwrap()
            .receipt
            .logs()
            .len(),
        2
    );

    // signer1 delegates to simple storage contract
    let auth = signer1
        .get_signed_authorization(set_arg_contract_address, 3)
        .unwrap();

    // signer2 executes the transaction
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![
            signer2
                .sign_eip7702_transaction(
                    Address::ZERO,
                    LogsContract::default().publish_event("helo".to_string()),
                    2,
                    vec![auth],
                )
                .unwrap(),
            signer2
                .sign_default_transaction(
                    TxKind::Call(signer1.address()),
                    SimpleStorageContract::default().set_call_data(100),
                    3,
                    0,
                )
                .unwrap(),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let signer1_account_info_post_tx = evm
        .account_info(&signer1.address(), &mut working_set)
        .unwrap();

    assert_eq!(signer1_account_info_post_tx.nonce, 4);

    assert_eq!(
        signer1_account_info_post_tx.balance,
        signer1_account_info_pre_delegate.balance,
    );

    assert_eq!(
        evm.offchain_code.get(
            &signer1_account_info_post_tx.code_hash.unwrap(),
            &mut working_set.offchain_state()
        ),
        Some(Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: set_arg_contract_address,
            version: 0,
            raw: [
                Bytes::from_hex("0xef0100").unwrap(),
                Bytes::from(set_arg_contract_address.to_vec())
            ]
            .concat()
            .into()
        }))
    );
    // and assert storage change
    assert_eq!(
        evm.storage_get(&signer1.address(), &U256::ZERO, &mut working_set)
            .unwrap_or_default(),
        U256::from(100)
    );
    // let's try the same thing with eth_call
    assert_eq!(
        evm.get_call(
            TransactionRequest::default()
                .to(signer1.address())
                .input(TransactionInput::from(
                    SimpleStorageContract::default().get_call_data()
                )),
            None,
            None,
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap(),
        Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000064")
            .unwrap()
    );

    // signer1 delegates to log contract with wrong nonce
    let auth = signer1
        .get_signed_authorization(log_contract_address, 1)
        .unwrap();

    // signer2 executes the transaction
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![signer2
            .sign_eip7702_transaction(
                Address::ZERO,
                LogsContract::default().publish_event("helo".to_string()),
                4,
                vec![auth],
            )
            .unwrap()];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // since nonce was wrong we should see no change
    assert_eq!(
        evm.offchain_code.get(
            &signer1_account_info_post_tx.code_hash.unwrap(),
            &mut working_set.offchain_state()
        ),
        Some(Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: set_arg_contract_address,
            version: 0,
            raw: [
                Bytes::from_hex("0xef0100").unwrap(),
                Bytes::from(set_arg_contract_address.to_vec())
            ]
            .concat()
            .into()
        }))
    );

    assert_eq!(signer1_account_info_post_tx.nonce, 4);
}

#[test]
fn test_min_base_fee_tangelo() {
    let (config, _dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);
    let l1_fee_rate = 0;

    // produce empty blocks to reduce base fee to the minimum for tangerine (10_000_000)
    for l2_height in 2..1600 {
        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: [10u8; 32],
            current_spec: SovSpecId::Tangerine,
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&[98u8; 32], &mut working_set.accessory_state());
    }

    let block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();
    assert_eq!(block.header.base_fee_per_gas.unwrap(), 10_000_000);

    // produce empty blocks to reduce base fee to the minimum for Tangelo (1_000_000)
    for l2_height in 1600..3200 {
        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: [10u8; 32],
            current_spec: SovSpecId::Tangelo,
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
        evm.end_l2_block_hook(&l2_block_info, &mut working_set);
        evm.finalize_hook(&[98u8; 32], &mut working_set.accessory_state());
    }

    let block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Latest),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap()
        .unwrap();
    assert_eq!(block.header.base_fee_per_gas.unwrap(), 1_000_000);
}

/// Test 1-a: Factory creates, calls selfdestruct, then tries to recreate - ALL in ONE transaction.
/// Per EIP-6780, SELFDESTRUCT marks the contract for destruction, but code/storage is only
/// cleared at the END of the transaction. So recreation at same address in the same tx
/// should FAIL because the account still has code at the time of the second CREATE2.
/// The factory asserts the deployment, so the transaction should revert.
/// Uses SpecialContract which sets x=42, y=100 in constructor.
/// Also prefunds the target address to verify balance stays after tx revert.
#[test]
fn test_create2_selfdestruct_recreate_same_tx() {
    use crate::smart_contracts::{Create2Factory1aContract, SpecialContractContract};

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());

    let factory_addr = dev_signer.address().create(0);
    let l1_fee_rate = 0;
    let l2_height = 2;

    // Calculate target address upfront so we can prefund it
    let factory_contract = Create2Factory1aContract::default();
    let special_contract = SpecialContractContract::default();
    let init_code = special_contract.byte_code();
    let salt = B256::from([1u8; 32]);
    let beneficiary = address!("11115497b157177315e1204f52e588b393111111");
    let target_addr = Create2Factory1aContract::compute_address(factory_addr, salt, &init_code);
    let prefund_amount: u128 = 1_000_000_000_000_000; // 0.001 ETH

    // Block 1: Deploy Factory1a and prefund target address
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_factory =
            create_contract_message(&dev_signer, 0, Create2Factory1aContract::default());
        // Prefund the target address
        let prefund_tx = dev_signer
            .sign_default_transaction(TxKind::Call(target_addr), vec![], 1, prefund_amount)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_factory, prefund_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Verify factory deployed and target prefunded
    let factory_info = evm
        .account_info(&factory_addr, &mut working_set)
        .expect("factory should exist");
    assert_ne!(factory_info.code_hash, Some(KECCAK_EMPTY));

    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should exist after prefunding");
    assert_eq!(
        target_info.balance,
        U256::from(prefund_amount),
        "target should have prefunded balance"
    );

    // Block 2: Call deployDestroyRedeploy - creates, selfdestructs, tries to recreate in ONE tx
    // This should FAIL because the account still has code at the time of the second CREATE2
    let l2_height = 3;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data = factory_contract.deploy_destroy_redeploy(
            salt,
            Bytes::from(init_code.clone()),
            beneficiary,
        );
        let deploy_destroy_redeploy_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 2, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_destroy_redeploy_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Check receipt - should FAIL because recreation in same tx is not possible
    // (account still has code until end of tx, so CREATE2 fails with address collision)
    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();
    assert!(
        !receipts.last().unwrap().receipt.status(),
        "deployDestroyRedeploy should fail (can't recreate in same tx - account still has code)"
    );

    // The target address should still have the prefunded balance (tx reverted)
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should still exist with prefunded balance");
    assert_eq!(
        target_info.balance,
        U256::from(prefund_amount),
        "target should still have prefunded balance after tx revert"
    );
    // Target should have no code (it was just an EOA with balance, tx reverted before deployment)
    assert!(
        target_info.code_hash.is_none(),
        "target should have no code (tx reverted)"
    );

    // Beneficiary should NOT have received any funds (tx reverted)
    let beneficiary_info = evm.account_info(&beneficiary, &mut working_set);
    assert!(
        beneficiary_info.is_none(),
        "beneficiary should not have received any funds (tx reverted)"
    );
}

/// Test 1-b: TX1: Factory creates + calls selfdestruct | TX2: Factory recreates.
/// Since selfdestruct happened in same tx as creation, contract is fully destroyed.
/// Recreation in a later tx should succeed.
/// Uses SpecialContract which sets x=42, y=100 in constructor.
/// Also prefunds the target address to verify balance is zeroed after selfdestruct.
#[test]
fn test_create2_selfdestruct_same_tx_then_recreate() {
    use crate::smart_contracts::{Create2Factory1bContract, SpecialContractContract};

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());

    let l1_fee_rate = 0;
    let l2_height = 2;

    let factory_addr = dev_signer.address().create(0);

    // Calculate target address upfront so we can prefund it
    let factory_contract = Create2Factory1bContract::default();
    let special_contract = SpecialContractContract::default();
    let init_code = special_contract.byte_code();
    let salt = B256::from([1u8; 32]);
    let beneficiary = address!("11115497b157177315e1204f52e588b393111111");
    let target_addr = Create2Factory1bContract::compute_address(factory_addr, salt, &init_code);
    let prefund_amount: u128 = 1_000_000_000_000_000; // 0.001 ETH

    // Block 1: Deploy Factory1b and prefund target address
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_factory =
            create_contract_message(&dev_signer, 0, Create2Factory1bContract::default());
        // Prefund the target address
        let prefund_tx = dev_signer
            .sign_default_transaction(TxKind::Call(target_addr), vec![], 1, prefund_amount)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_factory, prefund_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Verify target was prefunded
    let target_info = evm.account_info(&target_addr, &mut working_set);
    assert!(
        target_info.is_some(),
        "target should exist after prefunding"
    );
    assert_eq!(
        target_info.unwrap().balance,
        U256::from(prefund_amount),
        "target should have prefunded balance"
    );

    // Block 2: TX1 - deployAndDestroy (create + selfdestruct in same tx)
    let l2_height = 3;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data =
            factory_contract.deploy_and_destroy(salt, Bytes::from(init_code.clone()), beneficiary);
        let deploy_and_destroy_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 2, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_and_destroy_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Target should be fully destroyed (same tx as creation)
    let target_info = evm.account_info(&target_addr, &mut working_set);
    // After EIP-6780 selfdestruct in same tx as creation, account should be gone
    assert!(
        target_info.as_ref().unwrap().code_hash.is_none(),
        "target should be destroyed when selfdestruct is in same tx as creation"
    );

    // Balance should be zero (sent to beneficiary)
    assert_eq!(
        target_info.as_ref().unwrap().balance,
        U256::ZERO,
        "target balance should be zero after selfdestruct"
    );

    // Beneficiary should have received the prefunded balance
    let beneficiary_info = evm
        .account_info(&beneficiary, &mut working_set)
        .expect("beneficiary should exist");
    assert_eq!(
        beneficiary_info.balance,
        U256::from(prefund_amount),
        "beneficiary should have received the prefunded balance"
    );

    // Storage should be cleared (EIP-6780: full destruction when selfdestruct in same tx as creation)
    let x_value = evm.storage_get(&target_addr, &U256::from(0), &mut working_set);
    assert!(
        x_value.is_none(),
        "storage slot 0 (x) should be cleared after selfdestruct"
    );
    let y_value = evm.storage_get(&target_addr, &U256::from(1), &mut working_set);
    assert!(
        y_value.is_none(),
        "storage slot 1 (y) should be cleared after selfdestruct"
    );

    // Block 3: TX2 - deployOnly (recreate at same address)
    let l2_height = 4;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data = factory_contract.deploy_only(salt, Bytes::from(init_code.clone()));
        let deploy_only_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 3, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_only_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Check receipt - recreation should succeed
    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();
    assert!(
        receipts.last().unwrap().receipt.status(),
        "recreation should succeed"
    );

    // Target should now exist with code and storage
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should exist after recreate");
    assert!(target_info.code_hash.is_some(), "target should have code");
    assert_ne!(
        target_info.code_hash.unwrap(),
        KECCAK_EMPTY,
        "target should have non-empty code"
    );
    assert_eq!(
        target_info.nonce, 1,
        "target nonce should be 1 after recreation"
    );

    // Storage should have x=42 and y=100 from the constructor (SpecialContract)
    let x_value = evm
        .storage_get(&target_addr, &U256::from(0), &mut working_set)
        .unwrap();
    assert_eq!(x_value, U256::from(42), "storage slot 0 (x) should be 42");
    let y_value = evm
        .storage_get(&target_addr, &U256::from(1), &mut working_set)
        .unwrap();
    assert_eq!(y_value, U256::from(100), "storage slot 1 (y) should be 100");
}

/// Test 2-a: TX1: Factory creates | TX2: ContractA calls selfdestruct + calls factory to recreate (in one tx).
/// Since the target was created in a PREVIOUS tx, EIP-6780 does NOT allow full destruction.
/// Recreation in same tx as selfdestruct should fail because account still exists (code/nonce).
/// Uses SpecialContract which sets x=42, y=100 in constructor.
#[test]
fn test_create2_then_selfdestruct_and_recreate_same_tx() {
    use crate::smart_contracts::{
        Create2Factory1bContract, SelfdestructAndRecreateContract, SpecialContractContract,
    };

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());

    let l1_fee_rate = 0;
    let l2_height = 2;

    // Block 1: Deploy Factory1b and SelfdestructAndRecreate (Contract A)
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let factory_addr = dev_signer.address().create(0);

    // ContractA is deployed with nonce 1, compute its address
    let contract_a_addr = dev_signer.address().create(1);

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_factory =
            create_contract_message(&dev_signer, 0, Create2Factory1bContract::default());
        let deploy_contract_a =
            create_contract_message(&dev_signer, 1, SelfdestructAndRecreateContract::default());

        evm.call(
            CallMessage {
                txs: vec![deploy_factory, deploy_contract_a],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Block 2: TX1 - Create the target via deployOnly
    let l2_height = 3;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let factory_contract = Create2Factory1bContract::default();
    // SpecialContract sets x=42, y=100 in constructor
    let special_contract = SpecialContractContract::default();
    let init_code = special_contract.byte_code();
    let salt = B256::from([1u8; 32]);
    let beneficiary = address!("11115497b157177315e1204f52e588b393111111");
    let prefund_amount: u128 = 1_000_000_000_000_000; // 0.001 ETH

    let target_addr = Create2Factory1bContract::compute_address(factory_addr, salt, &init_code);

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data = factory_contract.deploy_only(salt, Bytes::from(init_code.clone()));
        let deploy_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 2, 0)
            .unwrap();
        // Fund the target contract after deployment
        let fund_tx = dev_signer
            .sign_default_transaction(TxKind::Call(target_addr), vec![], 3, prefund_amount)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_tx, fund_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Verify target was created and funded with storage (x=42, y=100 from SpecialContract)
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should exist");
    assert_ne!(target_info.code_hash.unwrap(), KECCAK_EMPTY);
    assert_eq!(target_info.nonce, 1, "target nonce should be 1");
    assert_eq!(
        target_info.balance,
        U256::from(prefund_amount),
        "target should have prefunded balance"
    );
    let x_value = evm
        .storage_get(&target_addr, &U256::from(0), &mut working_set)
        .unwrap();
    assert_eq!(x_value, U256::from(42), "x should be 42 after creation");
    let y_value = evm
        .storage_get(&target_addr, &U256::from(1), &mut working_set)
        .unwrap();
    assert_eq!(y_value, U256::from(100), "y should be 100 after creation");

    // Block 3: TX2 - ContractA calls selfdestruct on target, then tries to recreate (same tx)
    let l2_height = 4;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let contract_a = SelfdestructAndRecreateContract::default();

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data = contract_a.destroy_and_recreate(
            target_addr,
            beneficiary,
            factory_addr,
            salt,
            Bytes::from(init_code.clone()),
        );
        let nonce = evm
            .account_info(&dev_signer.address(), &mut working_set)
            .unwrap()
            .nonce;
        let destroy_recreate_tx = dev_signer
            .sign_default_transaction(TxKind::Call(contract_a_addr), call_data, nonce, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![destroy_recreate_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // The tx should FAIL because ContractA requires recreation to succeed,
    // but recreation fails (EIP-6780: target was created in a previous tx)
    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();
    assert!(
        !receipts.last().unwrap().receipt.status(),
        "tx should fail (recreation fails, ContractA reverts)"
    );

    // Since the tx reverted, ALL state changes are rolled back including the selfdestruct.
    // Target should still exist exactly as it was before TX2.
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should still exist");
    assert_ne!(
        target_info.code_hash.unwrap(),
        KECCAK_EMPTY,
        "target should have non-empty code"
    );
    assert_eq!(target_info.nonce, 1, "target nonce should still be 1");

    // Balance should still be the prefunded amount (tx reverted, so selfdestruct had no effect)
    assert_eq!(
        target_info.balance,
        U256::from(prefund_amount),
        "balance should still be prefunded amount (tx reverted)"
    );

    // Beneficiary should NOT have received any funds (tx reverted)
    let beneficiary_info = evm.account_info(&beneficiary, &mut working_set);
    assert!(
        beneficiary_info.is_none() || beneficiary_info.as_ref().unwrap().balance == U256::ZERO,
        "beneficiary should not have received any funds (tx reverted)"
    );

    // Storage should still exist (tx reverted, so selfdestruct had no effect)
    let x_value = evm
        .storage_get(&target_addr, &U256::from(0), &mut working_set)
        .unwrap();
    assert_eq!(
        x_value,
        U256::from(42),
        "storage should still exist (tx reverted)"
    );
    let y_value = evm
        .storage_get(&target_addr, &U256::from(1), &mut working_set)
        .unwrap();
    assert_eq!(
        y_value,
        U256::from(100),
        "storage should still exist (tx reverted)"
    );
}

/// Test 2-b: TX1: Factory creates | TX2: selfdestruct | TX3: Factory recreates.
/// Since the target was created in a PREVIOUS tx, EIP-6780 does NOT allow full destruction.
/// Recreation in a later tx should fail because account still exists (code/nonce).
/// Uses SpecialContract which sets x=42, y=100 in constructor.
#[test]
fn test_create2_then_selfdestruct_then_recreate() {
    use crate::smart_contracts::{Create2Factory1bContract, SpecialContractContract};

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());

    let l1_fee_rate = 0;
    let l2_height = 2;

    // Block 1: Deploy Factory1b
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let factory_addr = dev_signer.address().create(0);

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let deploy_factory =
            create_contract_message(&dev_signer, 0, Create2Factory1bContract::default());

        evm.call(
            CallMessage {
                txs: vec![deploy_factory],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Block 2: TX1 - Create the target via deployOnly
    let l2_height = 3;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    let factory_contract = Create2Factory1bContract::default();
    // SpecialContract sets x=42, y=100 in constructor
    let special_contract = SpecialContractContract::default();
    let init_code = special_contract.byte_code();
    let salt = B256::from([1u8; 32]);
    let beneficiary = address!("11115497b157177315e1204f52e588b393111111");
    let prefund_amount: u128 = 1_000_000_000_000_000; // 0.001 ETH

    let target_addr = Create2Factory1bContract::compute_address(factory_addr, salt, &init_code);

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        // Create target and then fund it (send ETH to the deployed contract)
        let call_data = factory_contract.deploy_only(salt, Bytes::from(init_code.clone()));
        let deploy_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 1, 0)
            .unwrap();
        // Fund the target contract after deployment
        let fund_tx = dev_signer
            .sign_default_transaction(TxKind::Call(target_addr), vec![], 2, prefund_amount)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![deploy_tx, fund_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Verify target was created and funded
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should exist");
    assert_ne!(target_info.code_hash.unwrap(), KECCAK_EMPTY);
    assert_eq!(
        target_info.balance,
        U256::from(prefund_amount),
        "target should have prefunded balance"
    );

    // Block 3: TX2 - Call selfdestruct on target
    let l2_height = 4;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        // Call die() on target using SpecialContract's die function
        let call_data = special_contract.die(beneficiary);
        let selfdestruct_tx = dev_signer
            .sign_default_transaction(TxKind::Call(target_addr), call_data, 3, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![selfdestruct_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Target should still exist with code (EIP-6780: not destroyed if not same-tx creation)
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should still exist");
    assert_ne!(
        target_info.code_hash.unwrap(),
        KECCAK_EMPTY,
        "target should still have code after selfdestruct"
    );
    assert_eq!(target_info.nonce, 1, "target nonce should still be 1");

    // Balance should be zero (transferred to beneficiary per EIP-6780)
    assert_eq!(
        target_info.balance,
        U256::ZERO,
        "target balance should be zero after selfdestruct"
    );

    // Beneficiary should have received the balance
    let beneficiary_info = evm
        .account_info(&beneficiary, &mut working_set)
        .expect("beneficiary should exist");
    assert_eq!(
        beneficiary_info.balance,
        U256::from(prefund_amount),
        "beneficiary should have received the target's balance"
    );

    // Storage should still exist (x=42, y=100 from SpecialContract)
    let x_value = evm
        .storage_get(&target_addr, &U256::from(0), &mut working_set)
        .unwrap();
    assert_eq!(x_value, U256::from(42), "storage should still exist");
    let y_value = evm
        .storage_get(&target_addr, &U256::from(1), &mut working_set)
        .unwrap();
    assert_eq!(y_value, U256::from(100), "storage should still exist");

    // Block 4: TX3 - Try to recreate at same address (should fail)
    let l2_height = 5;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let call_data = factory_contract.deploy_only(salt, Bytes::from(init_code.clone()));
        let recreate_tx = dev_signer
            .sign_default_transaction(TxKind::Call(factory_addr), call_data, 4, 0)
            .unwrap();

        evm.call(
            CallMessage {
                txs: vec![recreate_tx],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Check receipt - recreation should fail (revert)
    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();
    assert!(
        !receipts.last().unwrap().receipt.status(),
        "recreation should fail (address collision)"
    );

    // Target should still have the same code and storage (unchanged)
    let target_info = evm
        .account_info(&target_addr, &mut working_set)
        .expect("target should still exist");
    assert_ne!(
        target_info.code_hash.unwrap(),
        KECCAK_EMPTY,
        "target should still have code"
    );
    assert_eq!(target_info.nonce, 1, "target nonce should still be 1");
    let x_value = evm
        .storage_get(&target_addr, &U256::from(0), &mut working_set)
        .unwrap();
    assert_eq!(x_value, U256::from(42), "storage should be unchanged");
    let y_value = evm
        .storage_get(&target_addr, &U256::from(1), &mut working_set)
        .unwrap();
    assert_eq!(y_value, U256::from(100), "storage should be unchanged");
}

/// Test EIP-7702 delegation to SelfDestructorContract and calling die() in the same tx.
/// This tests what happens when an EOA delegates to a contract with selfdestruct
/// and die() is called in the same transaction where the authorization is applied.
/// We expect revm NOT to mark the account as selfdestructed (since it's an EOA with delegation)
/// and just perform a balance transfer.
#[test]
fn test_eip7702_selfdestruct_delegation() {
    let signer1 = TestSigner::new(SecretKey::new(&mut thread_rng())); // EOA that will delegate (no txs from this account)
    let signer1_initial_balance = 1000000000000000000u128; // 1 ETH

    let (config, dev_signer) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set, _spec_id, _ledger_db) =
        get_evm_with_spec(&config, SovSpecId::latest());

    let self_destructor_address = dev_signer.address().create(0);
    let beneficiary = address!("1111111111111111111111111111111111111111");

    let l1_fee_rate = 0;
    let mut l2_height = 2;

    // Block 1: signer2 deploys SelfDestructorContract & prefunds signer1
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 0, SelfDestructorContract::default()),
            // prefund signer1 tx
            dev_signer
                .sign_default_transaction(
                    TxKind::Call(signer1.address()),
                    vec![],
                    1,
                    signer1_initial_balance,
                )
                .unwrap(),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    // Verify SelfDestructorContract deployed
    let self_destructor_info = evm
        .account_info(&self_destructor_address, &mut working_set)
        .expect("SelfDestructorContract should exist");
    assert_ne!(self_destructor_info.code_hash, Some(KECCAK_EMPTY));
    assert_eq!(self_destructor_info.nonce, 1);

    // Verify signer1 has not made any txs
    let signer1_info_before = evm
        .account_info(&signer1.address(), &mut working_set)
        .unwrap();
    assert_eq!(signer1_info_before.nonce, 0);
    // Verify signer1's initial balance
    assert_eq!(
        signer1_info_before.balance,
        U256::from(signer1_initial_balance)
    );

    // Block 2: signer1 delegates to SelfDestructorContract and signer2 calls die() in same tx
    // signer1 authorizes delegation to the SelfDestructorContract (nonce 0 since no txs yet)
    let auth = signer1
        .get_signed_authorization(self_destructor_address, 0)
        .unwrap();

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

        // signer2 sends EIP-7702 tx with authorization that calls die() on signer1's address
        // The die() function will call selfdestruct(beneficiary)
        let die_calldata = SelfDestructorContract::default().selfdestruct(beneficiary);

        let transactions: Vec<RlpEvmTransaction> = vec![dev_signer
            .sign_eip7702_transaction(
                signer1.address(), // call signer1's address (which delegates to SelfDestructor)
                die_calldata,
                2,
                vec![auth],
            )
            .unwrap()];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Check receipt - tx should succeed
    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();
    let last_receipt = receipts.last().unwrap();
    assert!(
        last_receipt.receipt.status(),
        "EIP-7702 tx with selfdestruct should succeed"
    );

    // Check signer1's account - it should NOT be selfdestructed
    // The delegation should still be there and account should exist
    let signer1_info_after = evm
        .account_info(&signer1.address(), &mut working_set)
        .expect("signer1 should still exist after selfdestruct on delegated account");

    // Nonce should have increased (delegation consumes nonce) and selfdestruct doesn't reset to zero
    assert_eq!(signer1_info_after.nonce, 1);

    // The delegation should still be active
    assert_eq!(
        evm.offchain_code.get(
            &signer1_info_after.code_hash.unwrap(),
            &mut working_set.offchain_state()
        ),
        Some(Bytecode::Eip7702(Eip7702Bytecode {
            delegated_address: self_destructor_address,
            version: 0,
            raw: [
                Bytes::from_hex("0xef0100").unwrap(),
                Bytes::from(self_destructor_address.to_vec())
            ]
            .concat()
            .into()
        }))
    );

    // Balance should have been transferred to beneficiary (selfdestruct sends balance)
    let beneficiary_info = evm
        .account_info(&beneficiary, &mut working_set)
        .expect("beneficiary should exist after receiving funds");

    // signer1's balance should be 0 (all transferred to beneficiary)
    assert_eq!(
        signer1_info_after.balance,
        U256::ZERO,
        "signer1 balance should be 0 after selfdestruct"
    );

    // beneficiary should have received signer1's full initial balance
    assert_eq!(
        beneficiary_info.balance, signer1_initial_balance,
        "beneficiary should have received signer1's balance"
    );
}
