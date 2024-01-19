use std::str::FromStr;

use alloy_primitives::{FixedBytes, Uint};
use hex::FromHex;
use reth_primitives::{Address, BlockId, BlockNumberOrTag, Bytes, U64};
use reth_rpc_types::{CallInput, CallRequest};
use revm::primitives::{SpecId, B256, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};

use super::call_tests::{create_contract_transaction, publish_event_message, set_arg_message};
use crate::call::CallMessage;
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;
use crate::{
    AccountData, EthApiError, Evm, EvmConfig, Filter, FilterBlockOption, FilterSet, LogsContract,
    RlpEvmTransaction, RpcInvalidTransactionError, SimpleStorageContract,
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
            balance: U256::from_str("100000000000000000000").unwrap(),
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

    let contract_addr2: Address = Address::from_slice(
        hex::decode("eeb03d20dae810f52111b853b31c8be6f30f4cd3")
            .unwrap()
            .as_slice(),
    );
    // Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap();

    // println!("{:?}", contract_addr2);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

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
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

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

    evm.begin_slot_hook([10u8; 32], &[100u8; 32].into(), &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 7, SimpleStorageContract::default()),
            set_arg_message(contract_addr2, &dev_signer, 8, 478),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[101u8; 32].into(), &mut working_set.accessory_state());

    (evm, working_set, dev_signer)
}

#[test]
fn get_block_by_hash_test() {
    // make a block
    let (evm, mut working_set, _) = init_evm();

    let result = evm.get_block_by_hash([5u8; 32].into(), Some(false), &mut working_set);

    assert_eq!(result, Ok(None));

    let third_block = evm
        .get_block_by_hash(
            FixedBytes::from_hex(
                "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
            )
            .unwrap(),
            None,
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        third_block.header.number.unwrap(),
        alloy_primitives::U256::from(2u64)
    );

    assert_eq!(
        third_block.header.hash,
        Some(
            FixedBytes::from_hex(
                "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76"
            )
            .unwrap()
        )
    );

    assert_eq!(
        third_block.inner.header.gas_used,
        alloy_primitives::U256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000019c14"
        )
        .unwrap()
    );
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

    // Is there any need to check with details = true?
    let third_block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Number(2)),
            Some(false),
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    assert_eq!(
        third_block.header.hash,
        Some(
            FixedBytes::from_hex(
                "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76"
            )
            .unwrap()
        )
    );

    assert_eq!(
        third_block.header.number.unwrap(),
        alloy_primitives::U256::from(2u64)
    );

    assert_eq!(
        third_block.inner.header.gas_used,
        alloy_primitives::U256::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000019c14"
        )
        .unwrap()
    );
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

    let third_block_receipts = evm
        .get_block_receipts(
            BlockId::Number(BlockNumberOrTag::Number(2)),
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    assert_eq!(third_block_receipts.len(), 4);

    let cumulative_gas_used_arr = [
        "0x0000000000000000000000000000000000000000000000000000000000006720",
        "0x000000000000000000000000000000000000000000000000000000000000ce1c",
        "0x0000000000000000000000000000000000000000000000000000000000013518",
        "0x0000000000000000000000000000000000000000000000000000000000019c14",
    ]; // Removed _U256 suffix

    for i in 0..4 {
        assert_eq!(
            third_block_receipts[i].transaction_index,
            alloy_primitives::U64::from(i)
        );
        assert_eq!(third_block_receipts[i].logs.len(), 2);
        assert_eq!(
            third_block_receipts[i].cumulative_gas_used,
            U256::from_str(cumulative_gas_used_arr[i]).unwrap()
        );
    }

    let latest_block = evm
        .get_block_receipts(BlockId::Number(BlockNumberOrTag::Latest), &mut working_set)
        .unwrap()
        .unwrap();

    println!("{:?}", latest_block);

    assert_eq!(
        latest_block[0].block_hash.unwrap(),
        FixedBytes::from_hex("0xfa9fe269fb508f673f4ead3944ca034319cbd7d21904fbe0c8b760bccc8f7626")
            .unwrap()
    );

    assert_eq!(latest_block.len(), 2);

    let tx_hashes = [
        "0x8898708f7c0977ffd5356261a4854385b0547ecc8f7e0597147049750d009718",
        "0xbf12f1b29686aaeb0cef695ce4bb60cfc6411cde1bafc6c117e1ab2efcf72c55",
    ];

    for i in 0..2 {
        assert_eq!(
            latest_block[i].transaction_index,
            alloy_primitives::U64::from(i)
        );
        assert_eq!(
            latest_block[i].transaction_hash,
            Some(FixedBytes::from_hex(tx_hashes[i]).unwrap())
        );
    }
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

    let tx_hashes = [
        "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
        "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
        "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
        "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
    ];
    for i in 0..4 {
        let result =
            evm.get_transaction_by_block_hash_and_index(hash, U64::from(i), &mut working_set);

        assert_eq!(
            result.unwrap().unwrap().hash,
            FixedBytes::from_hex(tx_hashes[i]).unwrap()
        );
    }
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

    let tx_hashes = [
        "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
        "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
        "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
        "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
    ];
    for i in 0..4 {
        let result = evm.get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(2),
            U64::from(i),
            &mut working_set,
        );

        assert_eq!(
            result.unwrap().unwrap().hash,
            FixedBytes::from_hex(tx_hashes[i]).unwrap()
        );
    }
}

#[test]
fn call_test() {
    let (evm, mut working_set, signer) = init_evm();

    let fail_result = evm.get_call(
        CallRequest {
            from: Some(signer.address()),
            to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
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
            blob_versioned_hashes: Some(vec![]),
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(100)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(fail_result, Err(EthApiError::UnknownBlockNumber.into()));

    let contract = SimpleStorageContract::default();
    let call_data = contract.get_call_data().to_string();

    let nonce_too_low_result = evm.get_call(
        CallRequest {
            from: Some(signer.address()),
            to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
            gas: Some(U256::from(100000)),
            gas_price: Some(U256::from(100000000)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: CallInput::new(alloy_primitives::Bytes::from_str(&call_data).unwrap()),
            nonce: Some(U64::from(7)),
            chain_id: Some(U64::from(1u64)),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: Some(vec![]),
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(3)),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(
        nonce_too_low_result,
        Err(RpcInvalidTransactionError::NonceTooLow.into())
    );

    let result = evm
        .get_call(
            CallRequest {
                from: Some(signer.address()),
                to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
                gas: Some(U256::from(100000)),
                gas_price: Some(U256::from(10000)),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: None,
                input: CallInput::new(alloy_primitives::Bytes::from_str(&call_data).unwrap()),
                nonce: Some(U64::from(9)),
                chain_id: Some(U64::from(1u64)),
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: Some(vec![]),
                transaction_type: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockNumberOrTag::Number(1)),
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        result.to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
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

    assert_eq!(result, Err(EthApiError::UnknownBlockNumber.into()));

    let available_res = evm.eth_get_logs(
        Filter {
            block_option: FilterBlockOption::AtBlockHash(
                FixedBytes::from_hex(
                    "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                )
                .unwrap(),
            ),
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

    // TODO: Check this better.
    assert_eq!(available_res.unwrap().len(), 8);
}

#[test]
fn estimate_gas_test() {
    let (evm, mut working_set, signer) = init_evm();

    let fail_result = evm.eth_estimate_gas(
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
            blob_versioned_hashes: Some(vec![]),
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(100)),
        &mut working_set,
    );

    assert_eq!(fail_result, Err(EthApiError::UnknownBlockNumber.into()));

    let result = evm.eth_estimate_gas(
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
            blob_versioned_hashes: Some(vec![]),
            transaction_type: None,
        },
        Some(BlockNumberOrTag::Number(2)),
        &mut working_set,
    );

    assert_eq!(result.unwrap(), Uint::from_str("0x5208").unwrap().into());
}
