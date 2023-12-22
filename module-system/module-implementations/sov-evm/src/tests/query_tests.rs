use reth_primitives::{Address, BlockId, BlockNumberOrTag, Bytes, TransactionKind, U64};
use reth_rpc_types::{CallInput, CallRequest};
use revm::primitives::{SpecId, B256, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor, WorkingSet};

use super::call_tests::{create_contract_transaction, publish_event_message};
use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::query::EvmRpcImpl;
use crate::smart_contracts::{SelfDestructorContract, SimpleStorageContract, TestContract};
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;
use crate::{
    AccountData, BlockHashContract, Evm, EvmConfig, Filter, FilterSet, LogsContract,
    RlpEvmTransaction,
};

type C = DefaultContext;

/// Creates evm instance with 3 blocks (including genesis)
/// Block 1 has 2 transactions
/// Block 2 has 4 transactions
fn init_evm() -> (Evm<C>, WorkingSet<C>) {
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
        let context = C::new(sender_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 0, LogsContract::default()),
            publish_event_message(contract_addr, &dev_signer, 1, "hello".to_string()),
            publish_event_message(contract_addr, &dev_signer, 2, "hi".to_string()),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    evm.begin_slot_hook([8u8; 32], &[99u8; 32].into(), &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            publish_event_message(contract_addr, &dev_signer, 3, "hello2".to_string()),
            publish_event_message(contract_addr, &dev_signer, 4, "hi2".to_string()),
            publish_event_message(contract_addr, &dev_signer, 5, "hi3".to_string()),
            publish_event_message(contract_addr, &dev_signer, 6, "hi4".to_string()),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[100u8; 32].into(), &mut working_set.accessory_state());

    return (evm, working_set);
}

#[test]
fn get_block_by_hash_test() {
    // make a block
    let (evm, mut working_set) = init_evm();

    let result = evm.get_block_by_hash([5u8; 32].into(), Some(false), &mut working_set);

    assert_eq!(result, Ok(None));

    // TODO: check for existing block hash
}

#[test]
fn get_block_by_number_test() {
    // make a block
    let (evm, mut working_set) = init_evm();

    let result = evm.get_block_by_number(
        Some(BlockNumberOrTag::Number(1000)),
        Some(false),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    // TODO: check for existing block
}

#[test]
fn get_block_receipts_test() {
    // make a block
    let (evm, mut working_set) = init_evm();

    let result = evm.get_block_receipts(
        BlockId::Number(BlockNumberOrTag::Number(1000)),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    let result = evm.get_block_receipts(BlockId::from(B256::from([5u8; 32])), &mut working_set);

    assert_eq!(result, Ok(None));

    // TODO: check for existing block
}

#[test]
fn get_transaction_by_block_hash_and_index_test() {
    let (evm, mut working_set) = init_evm();

    let result = evm.get_transaction_by_block_hash_and_index(
        [0u8; 32].into(),
        U64::from(0),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    let hash = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Number(2)),
            Some(false),
            &mut working_set,
        )
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    // doesn't exist
    let result = evm.get_transaction_by_block_hash_and_index(hash, U64::from(4), &mut working_set);

    assert_eq!(result, Ok(None));

    // these should exist
    for i in 0..4 {
        let result =
            evm.get_transaction_by_block_hash_and_index(hash, U64::from(i), &mut working_set);

        assert!(result.unwrap().is_some());
    }

    // TODO: test correct cases
}

#[test]
fn get_transaction_by_block_number_and_index_test() {
    let (evm, mut working_set) = init_evm();

    let result = evm.get_transaction_by_block_number_and_index(
        BlockNumberOrTag::Number(100),
        U64::from(0),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    // doesn't exist
    let result = evm.get_transaction_by_block_number_and_index(
        BlockNumberOrTag::Number(1),
        U64::from(3),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    // these should exist
    for i in 0..3 {
        let result = evm.get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(1),
            U64::from(i),
            &mut working_set,
        );

        assert!(result.unwrap().is_some());
    }

    // TODO: test correct cases
}

#[test]
fn call_test() {
    todo!()
}

#[test]
fn logs_for_filter_test() {
    todo!()
}

#[test]
fn get_logs_in_block_range() {
    todo!()
}
