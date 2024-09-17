use std::collections::BTreeMap;

use reth_primitives::{address, b256, BlockId, BlockNumberOrTag, TxKind, U64};
use reth_rpc_eth_types::EthApiError;
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use reth_rpc_types::{AnyTransactionReceipt, Block, Rich};
use revm::primitives::{B256, U256};
use serde_json::json;

use crate::smart_contracts::SimpleStorageContract;
use crate::tests::queries::init_evm;

#[test]
fn get_block_by_hash_test() {
    // make a block
    let (evm, mut working_set, _, _) = init_evm();

    let result = evm.get_block_by_hash([5u8; 32].into(), Some(false), &mut working_set);

    assert_eq!(result, Ok(None));

    let third_block = evm
        .get_block_by_hash(
            b256!("2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9"),
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
    let (evm, mut working_set, _, _) = init_evm();

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
    let (evm, mut working_set, _, _) = init_evm();

    let result = evm.get_block_receipts(
        BlockId::Number(BlockNumberOrTag::Number(1000)),
        &mut working_set,
    );

    // AnyTransactionReceipt doesn't impl Eq or PartialEq
    // assert_eq!(result, Ok(None));
    // doesn't work
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let result = evm.get_block_receipts(BlockId::from(B256::from([5u8; 32])), &mut working_set);

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

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
    let (evm, mut working_set, _, _) = init_evm();

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
        b256!("2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99"),
        b256!("a69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8"),
        b256!("17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271"),
        b256!("d7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6"),
    ];

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let result =
            evm.get_transaction_by_block_hash_and_index(hash, U64::from(i), &mut working_set);

        assert_eq!(result.unwrap().unwrap().hash, *tx_hash);
    }
}

#[test]
fn get_transaction_by_block_number_and_index_test() {
    let (evm, mut working_set, _, _) = init_evm();

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
        b256!("2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99"),
        b256!("a69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8"),
        b256!("17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271"),
        b256!("d7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6"),
    ];
    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let result = evm.get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(2),
            U64::from(i),
            &mut working_set,
        );

        assert_eq!(result.unwrap().unwrap().hash, *tx_hash);
    }
}

#[test]
fn get_block_transaction_count_by_hash_test() {
    let (evm, mut working_set, _, _) = init_evm();

    let result =
        evm.eth_get_block_transaction_count_by_hash(B256::from([0u8; 32]), &mut working_set);
    // Non-existent blockhash should return None
    assert_eq!(result, Ok(None));

    let bock_hash_1 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(1)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    let result = evm.eth_get_block_transaction_count_by_hash(bock_hash_1, &mut working_set);

    assert_eq!(result, Ok(Some(U256::from(3))));

    let bock_hash_2 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(2)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    let result = evm.eth_get_block_transaction_count_by_hash(bock_hash_2, &mut working_set);

    assert_eq!(result, Ok(Some(U256::from(4))));

    let bock_hash_3 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(3)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    let result = evm.eth_get_block_transaction_count_by_hash(bock_hash_3, &mut working_set);

    assert_eq!(result, Ok(Some(U256::from(2))));
}

#[test]
fn get_block_transaction_count_by_number_test() {
    let (evm, mut working_set, _, _) = init_evm();

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(5), &mut working_set);
    // Non-existent block number should return None
    assert_eq!(result, Ok(None));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(1), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(3))));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(2), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(4))));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(3), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(2))));
}

#[test]
fn call_test() {
    let (evm, mut working_set, signer, _) = init_evm();

    let fail_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(address!(
                "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
            ))),
            gas: Some(100000),
            gas_price: Some(100000000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: None.into(),
            nonce: Some(7u64),
            chain_id: Some(1u64),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            transaction_type: None,
            sidecar: None,
        },
        Some(BlockId::Number(BlockNumberOrTag::Number(100))),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(fail_result, Err(EthApiError::UnknownBlockNumber.into()));
    working_set.unset_archival_version();

    let contract = SimpleStorageContract::default();
    let call_data = contract.get_call_data();

    let block_hash_3 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(3)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    let call_with_hash_nonce_too_low_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(address!(
                "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
            ))),
            gas: Some(100000),
            gas_price: Some(100000000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: TransactionInput::new(call_data.clone().into()),
            nonce: Some(7u64),
            chain_id: Some(1u64),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            transaction_type: None,
            sidecar: None,
        },
        Some(BlockId::Hash(block_hash_3.into())),
        None,
        None,
        &mut working_set,
    );

    let nonce_too_low_result = evm.get_call(
        TransactionRequest {
            from: Some(signer.address()),
            to: Some(TxKind::Call(address!(
                "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
            ))),
            gas: Some(100000),
            gas_price: Some(100000000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: Some(U256::from(100000000)),
            input: TransactionInput::new(call_data.clone().into()),
            nonce: Some(7u64),
            chain_id: Some(1u64),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            transaction_type: None,
            sidecar: None,
        },
        Some(BlockId::Number(BlockNumberOrTag::Number(3))),
        None,
        None,
        &mut working_set,
    );

    assert_eq!(call_with_hash_nonce_too_low_result, nonce_too_low_result);
    assert!(nonce_too_low_result.is_err());
    working_set.unset_archival_version();

    let latest_block_hash = evm
        .get_block_by_number(Some(BlockNumberOrTag::Latest), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash
        .unwrap();

    let result = evm
        .get_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(address!(
                    "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
                ))),
                gas: Some(100000),
                gas_price: Some(10000),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: None,
                input: TransactionInput::new(call_data.clone().into()),
                nonce: None,
                chain_id: Some(1u64),
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                transaction_type: None,
                sidecar: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    let call_with_hash_result = evm
        .get_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(address!(
                    "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
                ))),
                gas: Some(100000),
                gas_price: Some(10000),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: None,
                input: TransactionInput::new(call_data.clone().into()),
                nonce: None,
                chain_id: Some(1u64),
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                transaction_type: None,
                sidecar: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Hash(latest_block_hash.into())),
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(call_with_hash_result, result);
    assert_eq!(
        result.to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
    working_set.unset_archival_version();

    let result = evm
        .get_call(
            TransactionRequest {
                from: Some(signer.address()),
                to: Some(TxKind::Call(address!(
                    "eeb03d20dae810f52111b853b31c8be6f30f4cd3"
                ))),
                gas: None,
                gas_price: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                value: None,
                input: TransactionInput::new(call_data.into()),
                nonce: None,
                chain_id: None,
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
                transaction_type: None,
                sidecar: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
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
    // https://github.com/chainwayxyz/citrea/issues/134
}

fn check_against_third_block(block: &Rich<Block>) {
    // details = false
    let mut inner_block = serde_json::from_value::<Block>(json!({
        "hash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
        "parentHash": "0x97dcd6347f726d864f7b4e2f279f535f0e050bdba9da89e9b2cc744897565432",
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
        "size": "0x54b",
    })).unwrap();

    inner_block.other.insert(
        "l1FeeRate".to_string(),
        serde_json::Value::Number(serde_json::Number::from(1)),
    );

    inner_block.other.insert(
        "l1Hash".to_string(),
        serde_json::Value::String(
            "0x0808080808080808080808080808080808080808080808080808080808080808".to_string(),
        ),
    );

    let rich_block: Rich<Block> = Rich {
        inner: inner_block,
        extra_info: BTreeMap::new(),
    };

    assert_eq!(block, &rich_block);
}

fn check_against_third_block_receipts(receipts: Vec<AnyTransactionReceipt>) {
    let test_receipts = serde_json::from_value::<Vec<AnyTransactionReceipt>>(json!([
    {
        "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
        "transactionIndex": "0x0",
        "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x6720",
        "gasUsed": "0x6720",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "l1FeeRate": "0x1",
        "l1DiffSize": "0x60",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
        "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0xce1c",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "l1FeeRate": "0x1",
        "l1DiffSize": "0x60",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
        "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x13518",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "l1FeeRate": "0x1",
        "l1DiffSize": "0x60",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
        "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
        "blockNumber": "0x2",
        "cumulativeGasUsed": "0x19c14",
        "gasUsed": "0x66fc",
        "effectiveGasPrice": "0x2dbf4076",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "l1FeeRate": "0x1",
        "l1DiffSize": "0x60",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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
                "blockHash": "0x2d7962c316685635252886d6801a553139e94e3b7d2b678f8c9d974a54e24ab9",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
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

    let receipts = serde_json::to_string(&receipts).unwrap();
    let expected = serde_json::to_string(&test_receipts).unwrap();

    assert_eq!(receipts, expected)
}
