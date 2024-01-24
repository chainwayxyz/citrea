use std::collections::BTreeMap;
use std::str::FromStr;

use alloy_primitives::{FixedBytes, Uint};
use hex::FromHex;
use reth_primitives::{Address, BlockId, BlockNumberOrTag, Bytes, U64};
use reth_rpc_types::{Block, CallInput, CallRequest, Rich, TransactionReceipt};
use revm::primitives::{SpecId, B256, KECCAK_EMPTY, U256};
use serde_json::json;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_state::{DefaultStorageSpec, ProverStorage, Storage};

use super::call_tests::{create_contract_transaction, publish_event_message, set_arg_message};
use crate::call::CallMessage;
use crate::tests::genesis_tests::GENESIS_STATE_ROOT;
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

    let (evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

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

    commit(working_set, prover_storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

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

    commit(working_set, prover_storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

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

    commit(working_set, prover_storage.clone());

    let working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

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

    check_against_third_block(&third_block);
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
    let block = evm
        .get_block_by_number(
            Some(BlockNumberOrTag::Number(2)),
            Some(false),
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    check_against_third_block(&block);
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

    check_against_third_block_receipts(third_block_receipts);
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

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let result =
            evm.get_transaction_by_block_hash_and_index(hash, U64::from(i), &mut working_set);

        assert_eq!(
            result.unwrap().unwrap().hash,
            FixedBytes::from_hex(tx_hash).unwrap()
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
    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let result = evm.get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(2),
            U64::from(i),
            &mut working_set,
        );

        assert_eq!(
            result.unwrap().unwrap().hash,
            FixedBytes::from_hex(tx_hash).unwrap()
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
    working_set.unset_archival_version();

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
    working_set.unset_archival_version();

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
                nonce: None,
                chain_id: Some(U64::from(1u64)),
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: Some(vec![]),
                transaction_type: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockNumberOrTag::Latest),
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        result.to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
    working_set.unset_archival_version();

    let result = evm
        .get_call(
            CallRequest {
                from: Some(signer.address()),
                to: Some(Address::from_str("0xeeb03d20dae810f52111b853b31c8be6f30f4cd3").unwrap()),
                gas: None,
                gas_price: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: None,
                input: CallInput::new(alloy_primitives::Bytes::from_str(&call_data).unwrap()),
                nonce: None,
                chain_id: None,
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                transaction_type: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockNumberOrTag::Latest),
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        result.to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
    working_set.unset_archival_version();

    // TODO: Test these even further, to the extreme.
    // https://github.com/chainwayxyz/secret-sovereign-sdk/issues/134
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
    working_set.unset_archival_version();

    let contract = SimpleStorageContract::default();
    let call_data = contract.get_call_data().to_string();

    let result = evm.eth_estimate_gas(
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
        Some(BlockNumberOrTag::Latest),
        &mut working_set,
    );

    assert_eq!(result.unwrap(), Uint::from_str("0x5bde").unwrap());
    working_set.unset_archival_version();

    // TODO: Test these even further, to the extreme.
    // https://github.com/chainwayxyz/secret-sovereign-sdk/issues/134
}

pub(crate) fn get_evm_with_storage(
    config: &EvmConfig,
) -> (
    Evm<C>,
    WorkingSet<DefaultContext>,
    ProverStorage<DefaultStorageSpec, SnapshotManager>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    let mut genesis_state_root = [0u8; 32];
    genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    evm.finalize_hook(
        &genesis_state_root.into(),
        &mut working_set.accessory_state(),
    );
    (evm, working_set, prover_storage)
}

fn commit(
    working_set: WorkingSet<DefaultContext>,
    storage: ProverStorage<DefaultStorageSpec, SnapshotManager>,
) {
    // Save checkpoint
    let mut checkpoint = working_set.checkpoint();

    let (cache_log, witness) = checkpoint.freeze();

    let (_, authenticated_node_batch) = storage
        .compute_state_update(cache_log, &witness)
        .expect("jellyfish merkle tree update must succeed");

    let working_set = checkpoint.to_revertable();

    let accessory_log = working_set.checkpoint().freeze_non_provable();

    storage.commit(&authenticated_node_batch, &accessory_log);
}

fn check_against_third_block(block: &Rich<Block>) {
    // details = false
    let inner_block = serde_json::from_value::<Block>(json!({
        "hash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
        "parentHash": "0xddd453655668dbc6c321f40f377574791c2ea377c8407e302b0af5d45e5424a0",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": "0x0000000000000000000000000000000000000000",
        "stateRoot": "0x6464646464646464646464646464646464646464646464646464646464646464",
        "transactionsRoot": "0xef32d81a36e83472e84e033022e11d89a50d466cacc17bac6be1c981205330a3",
        "receiptsRoot": "0xf966e7c620235a408862e853eb0cd7e74c28abac1dece96c4440cd5b991d9058",
        "logsBloom": "0x00000000000000000000000000004000001000000000000000002000000000000000801000000000200000000000000000000000000000000000000000000000000020000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000040000000000000000000000800000000001100800000000000000000000000000000044000000000004000000000000000003000000000020001000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000010000080000000000000000",
        "difficulty": "0x0",
        "number": "0x2",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x19c14",
        "timestamp": "0x18",
        "extraData": "0x",
        "mixHash": "0x0808080808080808080808080808080808080808080808080808080808080808",
        "nonce": "0x0000000000000000",
        "baseFeePerGas": "0x2dbf4076",
        "totalDifficulty": "0x0",
        "uncles": [],
        "transactions": [
            "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
            "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
            "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
            "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6"
        ],
        "size": null
    })).unwrap();

    let rich_block: Rich<Block> = Rich {
        inner: inner_block,
        extra_info: BTreeMap::new(),
    };

    assert_eq!(block, &rich_block);
}

fn check_against_third_block_receipts(receipts: Vec<TransactionReceipt>) {
    let test_receipts = serde_json::from_value::<Vec<TransactionReceipt>>(json!([
    {
        "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
        "transactionIndex": "0x0",
        "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x6720",
        "gasUsed": "0x6720",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "contractAddress": null,
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x6d91615c65c0e8f861b0fbfce2d9897fb942293e341eda10c91a6912c4f32668"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
                "transactionIndex": "0x0",
                "logIndex": "0x0",
                "removed": false
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "data": "0x",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
                "transactionIndex": "0x0",
                "logIndex": "0x1",
                "removed": false
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000801000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000000000000000000000003000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000080000000000000000",
        "status": "0x1",
        "type": "0x2"
    },
    {
        "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
        "transactionIndex": "0x1",
        "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0xce1c",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "contractAddress": null,
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x63b901bb1c5ce387d96b2fa4dea95d718cf56095f6c1c7539385849cc23324e1"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
                "transactionIndex": "0x1",
                "logIndex": "0x2",
                "removed": false
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "data": "0x",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
                "transactionIndex": "0x1",
                "logIndex": "0x3",
                "removed": false
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000001000000000000000002000000000000000801000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000000000000000000000001000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000000000000000000000",
        "status": "0x1",
        "type": "0x2"
    },
    {
        "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
        "transactionIndex": "0x2",
        "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x13518",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "contractAddress": null,
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x5188fc8ba319bea37b8a074fdec21db88eef23191a849074ae8d6df8b2a32364"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
                "transactionIndex": "0x2",
                "logIndex": "0x4",
                "removed": false
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "data": "0x",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
                "transactionIndex": "0x2",
                "logIndex": "0x5",
                "removed": false
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000040000000000000000000000800000000001100800000000000000000000000000000044000000000000000000000000000001000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000010000000000000000000000",
        "status": "0x1",
        "type": "0x2"
    },
    {
        "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
        "transactionIndex": "0x3",
        "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x19c14",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "contractAddress": null,
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x29d61b64fc4b3d3e07e2692f6bc997236f115e546fae45393595f0cb0acbc4a0"
                ],
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
                "transactionIndex": "0x3",
                "logIndex": "0x6",
                "removed": false
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "data": "0x",
                "blockHash": "0x463f932c9ef1c01a59f2495ddcb7ae16d1a4afc2b5f38998486c4bf16cc94a76",
                "blockNumber": "0x2",
                "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
                "transactionIndex": "0x3",
                "logIndex": "0x7",
                "removed": false
            }
        ],
        "logsBloom": "0x00000000000000000000000000004000000000000000000000000000000000000000801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000004000000000000000001000000000020001000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000000000000000000000",
        "status": "0x1",
        "type": "0x2"
    }])).unwrap();

    assert_eq!(receipts, test_receipts)
}
