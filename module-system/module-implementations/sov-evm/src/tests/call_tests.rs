use reth_primitives::{Address, Bytes, TransactionKind};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module};

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::smart_contracts::{SelfDestructorContract, SimpleStorageContract, TestContract};
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;
use crate::{AccountData, EvmConfig};
type C = DefaultContext;

#[test]
fn call_test() {
    let dev_signer: TestSigner = TestSigner::new_random();
    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from(1000000000),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
        }],
        // SHANGAI instead of LATEST
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set) = get_evm(&config);

    let contract_addr: Address = Address::from_slice(
        hex::decode("819c5497b157177315e1204f52e588b393771719")
            .unwrap()
            .as_slice(),
    );

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address);

        let messages = vec![
            create_contract_message(&dev_signer, 0, SimpleStorageContract::default()),
            set_arg_message(contract_addr, &dev_signer, 1, set_arg),
        ];
        for tx in messages {
            evm.call(tx, &context, &mut working_set).unwrap();
        }
    }
    evm.end_slot_hook(&mut working_set);

    let db_account = evm.accounts.get(&contract_addr, &mut working_set).unwrap();
    let storage_value = db_account
        .storage
        .get(&U256::ZERO, &mut working_set)
        .unwrap();

    assert_eq!(U256::from(set_arg), storage_value);
    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![]
                },
                gas_used: 132943,
                log_index_start: 0,
                error: None
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![]
                },
                gas_used: 43730,
                log_index_start: 0,
                error: None
            }
        ]
    )
}

#[test]
fn failed_transaction_test() {
    let dev_signer: TestSigner = TestSigner::new_random();
    let (evm, mut working_set) = get_evm(&EvmConfig::default());
    let working_set = &mut working_set;

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address);
        let messages = vec![create_contract_message(
            &dev_signer,
            0,
            SimpleStorageContract::default(),
        )];

        for tx in messages {
            evm.call(tx, &context, working_set).unwrap();
        }
    }
    evm.end_slot_hook(working_set);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [Receipt {
            receipt: reth_primitives::Receipt {
                tx_type: reth_primitives::TxType::EIP1559,
                success: false,
                cumulative_gas_used: 0,
                logs: vec![]
            },
            gas_used: 0,
            log_index_start: 0,
            error: Some(revm::primitives::EVMError::Transaction(
                revm::primitives::InvalidTransaction::LackOfFundForMaxFee {
                    fee: 1_000_000u64,
                    balance: U256::ZERO
                }
            ))
        }]
    )
}

#[test]
fn self_destruct_test() {
    let signer_balance: u64 = 10000000000000000;
    let contract_balance: u64 = 1000000000000000;

    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr: Address = Address::from_slice(
        hex::decode("819c5497b157177315e1204f52e588b393771719")
            .unwrap()
            .as_slice(),
    );
    // address used in selfdestruct
    let die_to_address = Address::from_slice(
        hex::decode("11115497b157177315e1204f52e588b393111111")
            .unwrap()
            .as_slice(),
    );

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from(signer_balance),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address);

        // deploy selfdestruct contract
        evm.call(
            create_contract_message(&dev_signer, 0, SelfDestructorContract::default()),
            &context,
            &mut working_set,
        )
        .unwrap();

        // send some money to the selfdestruct contract
        evm.call(
            send_money_to_contract_message(contract_addr, &dev_signer, 1, contract_balance as u128),
            &context,
            &mut working_set,
        )
        .unwrap();

        // set some variable in the contract
        evm.call(
            set_selfdestruct_arg_message(contract_addr, &dev_signer, 2, 123),
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let db_contract = evm
        .accounts
        .get(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to ocntract
    assert_eq!(db_contract.info.balance, U256::from(contract_balance));

    // Test if we managed to set the variable in the contract
    assert_eq!(
        db_contract
            .storage
            .get(&U256::from(0), &mut working_set)
            .unwrap(),
        U256::from(123)
    );

    // Test if the key is set in the keys statevec
    assert_eq!(db_contract.keys.len(&mut working_set), 1);

    evm.begin_slot_hook([5u8; 32], &[99u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address);
        // selfdestruct
        evm.call(
            selfdestruct_message(contract_addr, &dev_signer, 3, die_to_address),
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_slot_hook(&mut working_set);
    let db_contract = evm
        .accounts
        .get(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    let db_account = evm
        .accounts
        .get(&die_to_address, &mut working_set)
        .expect("die to address should exist");

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert_eq!(receipts[0].receipt.success, true);

    // after self destruct, contract balance should be 0,
    assert_eq!(db_contract.info.balance, U256::from(0));

    // the to address balance should be equal to contract balance
    assert_eq!(db_account.info.balance, U256::from(contract_balance));

    // the codehash should be 0
    assert_eq!(db_contract.info.code_hash, Default::default());

    // the nonce should be 0
    assert_eq!(db_contract.info.nonce, 0);

    // the storage should be empty
    assert_eq!(
        db_contract.storage.get(&U256::from(0), &mut working_set),
        None
    );

    // the keys should be empty
    assert_eq!(db_contract.keys.len(&mut working_set), 0);
}

fn create_contract_message<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> CallMessage {
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Create,
            contract.byte_code().to_vec(),
            nonce,
            0,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn set_selfdestruct_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> CallMessage {
    let contract = SimpleStorageContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.set_call_data(set_arg))).unwrap(),
            nonce,
            0,
        )
        .unwrap();

    CallMessage { tx: signed_tx }
}

fn set_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> CallMessage {
    let contract = SimpleStorageContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.set_call_data(set_arg))).unwrap(),
            nonce,
            0,
        )
        .unwrap();

    CallMessage { tx: signed_tx }
}

fn selfdestruct_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    to_address: Address,
) -> CallMessage {
    let contract = SelfDestructorContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.selfdestruct(to_address))).unwrap(),
            nonce,
            0,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn send_money_to_contract_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    value: u128,
) -> CallMessage {
    let signed_tx = signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            vec![].into(),
            nonce,
            value,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}
