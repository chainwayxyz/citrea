use std::str::FromStr;

use reth_primitives::{Address, BlockId, BlockNumberOrTag, Bytes, U64};
use reth_rpc_types::CallRequest;
use revm::primitives::{SpecId, B256, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};

use super::call_tests::{create_contract_transaction, publish_event_message};
use crate::call::CallMessage;
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;
use crate::{
    AccountData, EthApiError, Evm, EvmConfig, Filter, FilterBlockOption, FilterSet, LogsContract,
    RlpEvmTransaction,
};

type C = DefaultContext;

/// Creates evm instance with 3 blocks (including genesis)
/// Block 1 has 2 transactions
/// Block 2 has 4 transactions
fn init_evm() -> (Evm<C>, WorkingSet<C>, TestSigner) {
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

    (evm, working_set, dev_signer)
}

#[test]
fn get_block_by_hash_test() {
    // make a block
    let (evm, mut working_set, _) = init_evm();

    let result = evm.get_block_by_hash([5u8; 32].into(), Some(false), &mut working_set);

    assert_eq!(result, Ok(None));

    // TODO: check for existing block hash
}

#[test]
fn get_block_by_number_test() {
    // make a block
    let (evm, mut working_set, _) = init_evm();

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
    let (evm, mut working_set, _) = init_evm();

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
    let (evm, mut working_set, _) = init_evm();

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
    let (evm, mut working_set, _) = init_evm();

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
    let (evm, mut working_set, signer) = init_evm();

    let result = evm.get_call(
        CallRequest {
            from: Some(signer.address()),
            to: Some(Address::from_str("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5").unwrap()),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: None.into(),
            nonce: Some(U64::from(7)),
            chain_id: Some(U64::from(1u64)),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: vec![],
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(100)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result, Err(EthApiError::UnknownBlockNumber.into()));

    // TODO: test correct cases
}

#[test]
fn logs_for_filter_test() {
    let (evm, mut working_set, _) = init_evm();

    let result = evm.eth_get_logs(
        Filter {
            block_option: FilterBlockOption::AtBlockHash(B256::from([1u8; 32])),
            address: FilterSet::default(),
            topics: [
                FilterSet::default(),
                FilterSet::default(),
                FilterSet::default(),
                FilterSet::default(),
            ],
        },
        &mut working_set,
    );

    // see: https://github.com/chainwayxyz/secret-sovereign-sdk/issues/79
    assert_eq!(result, Err(EthApiError::UnknownBlockNumber.into()));

    // not checking from and to option, because they are checked against latest block number
    // can't force evm to throw error.

    // TODO: test correct cases
}

#[test]
fn estimate_gas_test() {
    let (evm, mut working_set, signer) = init_evm();

    let result = evm.get_call(
        CallRequest {
            from: Some(signer.address()),
            to: Some(Address::from_str("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5").unwrap()),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: None.into(),
            nonce: Some(U64::from(7)),
            chain_id: Some(U64::from(1u64)),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: vec![],
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(100)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(result, Err(EthApiError::UnknownBlockNumber.into()));

    // TODO: test correct cases
}
