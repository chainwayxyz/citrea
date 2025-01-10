use std::collections::BTreeMap;
use std::str::FromStr;

use alloy_eips::eip2930::{AccessList, AccessListItem, AccessListWithGasUsed};
use alloy_primitives::{address, b256, Address, TxKind, B256, U256, U64};
use alloy_rpc_types::{
    AnyNetworkBlock, AnyTransactionReceipt, TransactionInput, TransactionRequest,
};
use alloy_serde::OtherFields;
use reth_primitives::{BlockId, BlockNumberOrTag};
use reth_rpc_eth_types::EthApiError;
use serde_json::json;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::smart_contracts::{CallerContract, SimpleStorageContract};
use crate::tests::queries::{init_evm, init_evm_with_caller_contract};
use crate::tests::utils::get_fork_fn_only_fork1;
use crate::EstimatedDiffSize;

#[test]
fn get_block_by_hash_test() {
    // make a block
    let (evm, mut working_set, _, _, _) = init_evm();

    let result = evm.get_block_by_hash([5u8; 32].into(), Some(false), &mut working_set);

    assert_eq!(result, Ok(None));

    let third_block = evm
        .get_block_by_hash(
            b256!("27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d"),
            None,
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    // Including genesis
    check_against_third_block(&third_block);
}

#[test]
fn get_block_by_number_test() {
    // make a block
    let (evm, mut working_set, _, _, _) = init_evm();

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
    let (evm, mut working_set, _, _, _) = init_evm();

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
    let (evm, mut working_set, _, _, _) = init_evm();

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
        .hash;

    // doesn't exist
    let result = evm.get_transaction_by_block_hash_and_index(hash, U64::from(5), &mut working_set);

    assert_eq!(result, Ok(None));

    let tx_hashes = [
        b256!("29640d82d763831afa07d23c967d6a3149a1fec2cde106a5b5abee6c319b61f3"),
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
    let (evm, mut working_set, _, _, _) = init_evm();

    let result = evm.get_transaction_by_block_number_and_index(
        BlockNumberOrTag::Number(100),
        U64::from(0),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    // doesn't exist
    let result = evm.get_transaction_by_block_number_and_index(
        BlockNumberOrTag::Number(1),
        U64::from(6),
        &mut working_set,
    );

    assert_eq!(result, Ok(None));

    // these should exist
    for i in 0..6 {
        let result = evm.get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(1),
            U64::from(i),
            &mut working_set,
        );

        assert!(result.unwrap().is_some());
    }

    let tx_hashes = [
        b256!("29640d82d763831afa07d23c967d6a3149a1fec2cde106a5b5abee6c319b61f3"),
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
    let (evm, mut working_set, _, _, _) = init_evm();

    let result =
        evm.eth_get_block_transaction_count_by_hash(B256::from([0u8; 32]), &mut working_set);
    // Non-existent blockhash should return None
    assert_eq!(result, Ok(None));

    let block_hash_1 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(1)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash;

    let result = evm.eth_get_block_transaction_count_by_hash(block_hash_1, &mut working_set);

    assert_eq!(result, Ok(Some(U256::from(6))));

    let block_hash_2 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(2)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash;

    let result = evm.eth_get_block_transaction_count_by_hash(block_hash_2, &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(5))));

    let block_hash_3 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(3)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash;

    let result = evm.eth_get_block_transaction_count_by_hash(block_hash_3, &mut working_set);

    assert_eq!(result, Ok(Some(U256::from(3))));
}

#[test]
fn get_block_transaction_count_by_number_test() {
    let (evm, mut working_set, _, _, _) = init_evm();

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(5), &mut working_set);
    // Non-existent block number should return None
    assert_eq!(result, Ok(None));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(1), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(6))));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(2), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(5))));

    let result = evm
        .eth_get_block_transaction_count_by_number(BlockNumberOrTag::Number(3), &mut working_set);
    assert_eq!(result, Ok(Some(U256::from(3))));
}

#[test]
fn call_test() {
    let (evm, mut working_set, _, signer, _) = init_evm();

    let fail_result = evm.get_call_inner(
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
            authorization_list: None,
        },
        Some(BlockId::Number(BlockNumberOrTag::Number(100))),
        None,
        None,
        &mut working_set,
        get_fork_fn_only_fork1(),
    );

    assert_eq!(
        fail_result,
        Err(EthApiError::HeaderNotFound(BlockNumberOrTag::Number(100).into()).into())
    );
    working_set.unset_archival_version();

    let contract = SimpleStorageContract::default();
    let call_data = contract.get_call_data();

    let block_hash_3 = evm
        .get_block_by_number(Some(BlockNumberOrTag::Number(3)), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash;

    let call_with_hash_nonce_too_low_result = evm.get_call_inner(
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
            authorization_list: None,
        },
        Some(BlockId::Hash(block_hash_3.into())),
        None,
        None,
        &mut working_set,
        get_fork_fn_only_fork1(),
    );

    let nonce_too_low_result = evm.get_call_inner(
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
            authorization_list: None,
        },
        Some(BlockId::Number(BlockNumberOrTag::Number(3))),
        None,
        None,
        &mut working_set,
        get_fork_fn_only_fork1(),
    );

    assert_eq!(call_with_hash_nonce_too_low_result, nonce_too_low_result);
    assert!(nonce_too_low_result.is_err());
    working_set.unset_archival_version();

    let latest_block_hash = evm
        .get_block_by_number(Some(BlockNumberOrTag::Latest), None, &mut working_set)
        .unwrap()
        .unwrap()
        .header
        .hash;

    let result = evm
        .get_call_inner(
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
                authorization_list: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            None,
            None,
            &mut working_set,
            get_fork_fn_only_fork1(),
        )
        .unwrap();

    let call_with_hash_result = evm
        .get_call_inner(
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
                authorization_list: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Hash(latest_block_hash.into())),
            None,
            None,
            &mut working_set,
            get_fork_fn_only_fork1(),
        )
        .unwrap();

    assert_eq!(call_with_hash_result, result);
    assert_eq!(
        result.to_string(),
        "0x00000000000000000000000000000000000000000000000000000000000001de"
    );
    working_set.unset_archival_version();

    let result = evm
        .get_call_inner(
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
                authorization_list: None,
            },
            // How does this work precisely? In the first block, the contract was not there?
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            None,
            None,
            &mut working_set,
            get_fork_fn_only_fork1(),
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

fn check_against_third_block(block: &AnyNetworkBlock) {
    // details = false
    let inner_block = serde_json::from_value::<AnyNetworkBlock>(json!({
        "baseFeePerGas": "0x2de0b039",
        "blobGasUsed": "0",
        "excessBlobGas": "0",
        "difficulty": "0x0",
        "extraData": "0x",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0x2d700",
        "hash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "logsBloom": "0x00000000000000000000000000004000001000000000000000002000000000000000801000000000200000000000000000000000000800000000000000000000000020000000000800000000000000000000000000400000000000000000000008000000000000000000000000000400000000000008000000000000000000040040000000000000000000000800000000001100800000000010000000000000000000044000000000004000000000000000003000000000020001000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000010000080000000000000000",
        "miner": "0x0000000000000000000000000000000000000000",
        "mixHash": "0x0808080808080808080808080808080808080808080808080808080808080808",
        "nonce": "0x0000000000000000",
        "number": "0x2",
        "parentHash": "0x31d8faf0b907db5eb235801c97410b6013daca9d6c47ae45dfda0a84eef7b5c6",
        "receiptsRoot": "0x2147ba909c0456b68d818b3e1bc80dc83c8c38e0ad3a91de36d0a940c97681de",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x5c3",
        "stateRoot": "0x6464646464646464646464646464646464646464646464646464646464646464",
        "timestamp": "0x18",
        "totalDifficulty": "0x0",
        "transactions": [
            "0x29640d82d763831afa07d23c967d6a3149a1fec2cde106a5b5abee6c319b61f3",
            "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
            "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
            "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
            "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6"
        ],
        "transactionsRoot": "0x246f34a58de3339f3079ad70f5f8614bcec07244bf1957e271c74468e262cb31",
        "uncles": []
    })).unwrap();

    let mut rich_block: AnyNetworkBlock = AnyNetworkBlock {
        inner: inner_block.inner,
        other: OtherFields::new(BTreeMap::new()),
    };

    rich_block
        .other
        .insert("l1FeeRate".to_string(), "0x1".into());

    rich_block.other.insert(
        "l1Hash".to_string(),
        serde_json::Value::String(
            "0x0808080808080808080808080808080808080808080808080808080808080808".to_string(),
        ),
    );

    assert_eq!(block, &rich_block);
}

fn check_against_third_block_receipts(receipts: Vec<AnyTransactionReceipt>) {
    let test_receipts = serde_json::from_value::<Vec<AnyTransactionReceipt>>(json!(
        [
    {
        "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "blockNumber": "0x2",
        "contractAddress": null,
        "cumulativeGasUsed": "0x13aec",
        "effectiveGasPrice": "0x2de0b039",
        "from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
        "gasUsed": "0x13aec",
        "l1DiffSize": "0x5e",
        "l1FeeRate": "0x1",
        "logs": [
            {
                "address": "0x3100000000000000000000000000000000000001",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x000000000000000000000000000000000000000000000000000000000000000208080808080808080808080808080808080808080808080808080808080808082a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "logIndex": "0x0",
                "removed": false,
                "topics": [
                    "0x32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f"
                ],
                "transactionHash": "0x29640d82d763831afa07d23c967d6a3149a1fec2cde106a5b5abee6c319b61f3",
                "transactionIndex": "0x0"
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000040000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x1",
        "to": "0x3100000000000000000000000000000000000001",
        "transactionHash": "0x29640d82d763831afa07d23c967d6a3149a1fec2cde106a5b5abee6c319b61f3",
        "transactionIndex": "0x0",
        "type": "0x2"
    },
    {
        "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "blockNumber": "0x2",
        "contractAddress": null,
        "cumulativeGasUsed": "0x1a20c",
        "effectiveGasPrice": "0x2de0b039",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "gasUsed": "0x6720",
        "l1DiffSize": "0x1f",
        "l1FeeRate": "0x1",
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "logIndex": "0x1",
                "removed": false,
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x6d91615c65c0e8f861b0fbfce2d9897fb942293e341eda10c91a6912c4f32668"
                ],
                "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
                "transactionIndex": "0x1"
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x",
                "logIndex": "0x2",
                "removed": false,
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
                "transactionIndex": "0x1"
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000801000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000000000000000000000003000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000080000000000000000",
        "status": "0x1",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "transactionHash": "0x2ff3a833e99d5a97e26f912c2e855f95e2dda542c89131fea0d189889d384d99",
        "transactionIndex": "0x1",
        "type": "0x2"
    },
    {
        "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "blockNumber": "0x2",
        "contractAddress": null,
        "cumulativeGasUsed": "0x20908",
        "effectiveGasPrice": "0x2de0b039",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "gasUsed": "0x66fc",
        "l1DiffSize": "0x1f",
        "l1FeeRate": "0x1",
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "logIndex": "0x3",
                "removed": false,
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x63b901bb1c5ce387d96b2fa4dea95d718cf56095f6c1c7539385849cc23324e1"
                ],
                "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
                "transactionIndex": "0x2"
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x",
                "logIndex": "0x4",
                "removed": false,
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
                "transactionIndex": "0x2"
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000001000000000000000002000000000000000801000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000000000000000000000001000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000000000000000000000",
        "status": "0x1",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "transactionHash": "0xa69485c543cd51dc1856619f3ddb179416af040da2835a10405c856cd5fb41b8",
        "transactionIndex": "0x2",
        "type": "0x2"
    },
    {
        "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "blockNumber": "0x2",
        "contractAddress": null,
        "cumulativeGasUsed": "0x27004",
        "effectiveGasPrice": "0x2de0b039",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "gasUsed": "0x66fc",
        "l1DiffSize": "0x1f",
        "l1FeeRate": "0x1",
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "logIndex": "0x5",
                "removed": false,
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x5188fc8ba319bea37b8a074fdec21db88eef23191a849074ae8d6df8b2a32364"
                ],
                "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
                "transactionIndex": "0x3"
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x",
                "logIndex": "0x6",
                "removed": false,
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
                "transactionIndex": "0x3"
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000040000000000000000000000800000000001100800000000000000000000000000000044000000000000000000000000000001000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000010000000000000000000000",
        "status": "0x1",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "transactionHash": "0x17fa953338b32b30795ccb62f050f1c9bcdd48f4793fb2d6d34290b444841271",
        "transactionIndex": "0x3",
        "type": "0x2"
    },
    {
        "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
        "blockNumber": "0x2",
        "contractAddress": null,
        "cumulativeGasUsed": "0x2d700",
        "effectiveGasPrice": "0x2de0b039",
        "from": "0x9e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
        "gasUsed": "0x66fc",
        "l1DiffSize": "0x1f",
        "l1FeeRate": "0x1",
        "logs": [
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c48656c6c6f20576f726c64210000000000000000000000000000000000000000",
                "logIndex": "0x7",
                "removed": false,
                "topics": [
                    "0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7",
                    "0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719",
                    "0x29d61b64fc4b3d3e07e2692f6bc997236f115e546fae45393595f0cb0acbc4a0"
                ],
                "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
                "transactionIndex": "0x4"
            },
            {
                "address": "0x819c5497b157177315e1204f52e588b393771719",
                "blockHash": "0x27e01fc6e3aad6bde81589b349a9ecd036c60621625ed9e837cf1bb9f72c0d1d",
                "blockNumber": "0x2",
                "blockTimestamp": "0x18",
                "data": "0x",
                "logIndex": "0x8",
                "removed": false,
                "topics": [
                    "0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9",
                    "0x000000000000000000000000819c5497b157177315e1204f52e588b393771719"
                ],
                "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
                "transactionIndex": "0x4"
            }
        ],
        "logsBloom": "0x00000000000000000000000000004000000000000000000000000000000000000000801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000008000000000000000000000000000400000000000000000000000000000000000000000000000000000000000800000000001000800000000000000000000000000000044000000000004000000000000000001000000000020001000000000000000000000000000000000000000000000000000000000000010000000000000000000000400000000000000000000000800000000000000000000000000000",
        "status": "0x1",
        "to": "0x819c5497b157177315e1204f52e588b393771719",
        "transactionHash": "0xd7e5b2bce65678b5e1a4430b1320b18a258fd5412e20bd5734f446124a9894e6",
        "transactionIndex": "0x4",
        "type": "0x2"
    }])).unwrap();

    let receipts = serde_json::to_string(&receipts).unwrap();
    let expected = serde_json::to_string(&test_receipts).unwrap();

    assert_eq!(receipts, expected)
}

#[test]
fn test_queries_with_forks() {
    // 0x819c5497b157177315e1204f52e588b393771719 -- Storage contract
    // 0x5ccda3e6d071a059f00d4f3f25a1adc244eb5c93 -- Caller contract

    let (mut evm, mut working_set, signer, _) = init_evm_with_caller_contract();

    let l2_height = 2;

    let fork_fn = |num: u64| {
        if num < 3 {
            Fork::new(SovSpecId::Genesis, 0)
        } else {
            Fork::new(SovSpecId::Kumquat, 4)
        }
    };

    let caller = CallerContract::default();
    let input_data = caller.call_set_call_data(
        Address::from_str("0x819c5497b157177315e1204f52e588b393771719").unwrap(),
        42,
    );

    let tx_req_contract_call = TransactionRequest {
        from: Some(signer.address()),
        to: Some(TxKind::Call(address!(
            "5ccda3e6d071a059f00d4f3f25a1adc244eb5c93"
        ))),
        gas: Some(10000000),
        gas_price: Some(100),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        input: TransactionInput::new(input_data.into()),
        nonce: Some(3u64),
        chain_id: Some(1u64),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
        transaction_type: None,
        sidecar: None,
        authorization_list: None,
    };

    let no_access_list_pre_fork = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        fork_fn,
    );
    assert_eq!(
        no_access_list_pre_fork.clone().unwrap(),
        U256::from_str("0x54ef").unwrap()
    );

    let diff_size = evm
        .eth_estimate_diff_size_inner(
            tx_req_contract_call.clone(),
            None,
            &mut working_set,
            fork_fn,
        )
        .unwrap();
    assert_eq!(
        diff_size,
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x54ee","l1DiffSize":"0x60"}])
            .unwrap()
    );

    let form_access_list = evm
        .create_access_list_inner(
            tx_req_contract_call.clone(),
            None,
            &mut working_set,
            fork_fn,
        )
        .unwrap();

    assert_eq!(
        form_access_list,
        AccessListWithGasUsed {
            access_list: AccessList(vec![]),
            gas_used: U256::from_str("0x54ef").unwrap()
        }
    );

    let tx_req_with_access_list = TransactionRequest {
        access_list: Some(form_access_list.access_list.clone()),
        ..tx_req_contract_call.clone()
    };

    let with_access_list =
        evm.eth_estimate_gas_inner(tx_req_with_access_list, None, &mut working_set, fork_fn);
    assert_eq!(with_access_list.unwrap(), U256::from_str("0x54ef").unwrap());

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [1u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate: 0,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let no_access_list_post_fork = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        None,
        &mut working_set,
        fork_fn,
    );
    // After fork the gas cost is different.
    assert_eq!(
        no_access_list_post_fork.clone().unwrap(),
        U256::from_str("0x788c").unwrap()
    );

    let form_access_list = evm
        .create_access_list_inner(
            tx_req_contract_call.clone(),
            None,
            &mut working_set,
            fork_fn,
        )
        .unwrap();

    assert_eq!(
        form_access_list,
        AccessListWithGasUsed {
            access_list: AccessList(vec![AccessListItem {
                address: address!("819c5497b157177315e1204f52e588b393771719"),
                storage_keys: vec![b256!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                )]
            }]),
            gas_used: U256::from_str("0x775e").unwrap()
        }
    );

    let tx_req_with_access_list = TransactionRequest {
        access_list: Some(form_access_list.access_list.clone()),
        ..tx_req_contract_call.clone()
    };

    let with_access_list =
        evm.eth_estimate_gas_inner(tx_req_with_access_list, None, &mut working_set, fork_fn);
    assert_eq!(with_access_list.unwrap(), U256::from_str("0x775e").unwrap());

    let diff_size = evm
        .eth_estimate_diff_size_inner(
            tx_req_contract_call.clone(),
            None,
            &mut working_set,
            fork_fn,
        )
        .unwrap();

    assert_eq!(
        diff_size,
        serde_json::from_value::<EstimatedDiffSize>(json![{"gas":"0x788b","l1DiffSize":"0x35"}])
            .unwrap()
    );

    // Get pre fork estimated gas and expect it to still work same
    let no_access_list_genesis_after_fork = evm.eth_estimate_gas_inner(
        tx_req_contract_call.clone(),
        Some(BlockNumberOrTag::Number(2)),
        &mut working_set,
        fork_fn,
    );
    assert_eq!(
        no_access_list_genesis_after_fork.clone().unwrap(),
        no_access_list_pre_fork.clone().unwrap()
    );

    assert_ne!(
        no_access_list_pre_fork.clone().unwrap(),
        no_access_list_post_fork.unwrap()
    );
}
