use std::str::FromStr;

use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use ethers::abi::Address;
use ethers_core::abi::Bytes;
use reth_primitives::{BlockId, BlockNumberOrTag, B256};

use crate::evm::init_test_rollup;
use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT};

#[tokio::test]
async fn test_archival_state() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();

    run_archival_valid_tests(addr, &seq_test_client).await;
    run_archival_fail_tests(addr, &seq_test_client).await;

    seq_task.abort();
    Ok(())
}

async fn run_archival_fail_tests(addr: Address, seq_test_client: &TestClient) {
    let invalid_block_hash = B256::random();
    let invalid_block_balance = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();

    assert!(invalid_block_balance
        .to_string()
        .contains("unknown block number"));

    let invalid_block_balance = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();

    assert!(invalid_block_balance
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_storage = seq_test_client
        .eth_get_storage_at(
            addr,
            0u64.into(),
            Some(BlockId::Number(BlockNumberOrTag::Number(722))),
        )
        .await
        .unwrap_err();
    assert!(invalid_block_storage
        .to_string()
        .contains("unknown block number"));

    let invalid_block_storage = seq_test_client
        .eth_get_storage_at(
            addr,
            0u64.into(),
            Some(BlockId::Hash(invalid_block_hash.into())),
        )
        .await
        .unwrap_err();
    assert!(invalid_block_storage
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_code = seq_test_client
        .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();
    assert!(invalid_block_code
        .to_string()
        .contains("unknown block number"));

    let invalid_block_code = seq_test_client
        .eth_get_code(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();
    assert!(invalid_block_code
        .to_string()
        .contains("unknown block or tx index"));

    let invalid_block_tx_count = seq_test_client
        .eth_get_transaction_count(addr, Some(BlockId::Number(BlockNumberOrTag::Number(722))))
        .await
        .unwrap_err();
    assert!(invalid_block_tx_count
        .to_string()
        .contains("unknown block number"));

    let invalid_block_tx_count = seq_test_client
        .eth_get_transaction_count(addr, Some(BlockId::Hash(invalid_block_hash.into())))
        .await
        .unwrap_err();
    assert!(invalid_block_tx_count
        .to_string()
        .contains("unknown block or tx index"));
}

async fn run_archival_valid_tests(addr: Address, seq_test_client: &TestClient) {
    let latest_block_hash = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(None)
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                addr,
                0u64.into(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        0u64.into()
    );
    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                addr,
                0u64.into(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        Bytes::from([])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        Bytes::from([])
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        0
    );

    for _ in 0..8 {
        let _t = seq_test_client
            .send_eth(addr, None, None, None, 1u128)
            .await;
        seq_test_client.send_publish_batch_request().await;
    }
    let latest_block_hash = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(None)
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        8u64.into()
    );
    // assert_eq!(
    //     seq_test_client
    //         .eth_get_balance(addr, Some(BlockId::Hash(latest_block_hash.into())))
    //         .await
    //         .unwrap(),
    //     8u64.into()
    // );

    assert_eq!(
        seq_test_client.eth_get_balance(addr, None).await.unwrap(),
        8u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        8
    );
    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        8
    );

    for i in 1..8 {
        assert_eq!(
            seq_test_client
                .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(i))))
                .await
                .unwrap(),
            i.into()
        );

        let block_hash_i = B256::from_slice(
            seq_test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
                .await
                .hash
                .unwrap()
                .as_bytes(),
        );

        assert_eq!(
            seq_test_client
                .eth_get_balance(addr, Some(BlockId::Hash(block_hash_i.into())))
                .await
                .unwrap(),
            i.into()
        );

        assert_eq!(
            seq_test_client
                .eth_get_transaction_count(
                    Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                    Some(BlockId::Number(BlockNumberOrTag::Number(i)))
                )
                .await
                .unwrap(),
            i
        );

        assert_eq!(
            seq_test_client
                .eth_get_transaction_count(
                    Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                    Some(BlockId::Hash(block_hash_i.into()))
                )
                .await
                .unwrap(),
            i
        );
    }

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                0u64.into(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                0u64.into(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        0u64.into()
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
            .await
            .unwrap(),
        Bytes::from(vec![])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockId::Hash(latest_block_hash.into())))
            .await
            .unwrap(),
        Bytes::from(vec![])
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Number(BlockNumberOrTag::Latest))
            )
            .await
            .unwrap(),
        Bytes::from(vec![])
    );
    assert_eq!(
        seq_test_client
            .eth_get_code(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockId::Hash(latest_block_hash.into()))
            )
            .await
            .unwrap(),
        Bytes::from(vec![])
    );

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();

        let runtime_code = seq_test_client
            .deploy_contract_call(contract.byte_code(), None)
            .await
            .unwrap();

        let deploy_contract_req = seq_test_client
            .deploy_contract(contract.byte_code(), None)
            .await
            .unwrap();

        seq_test_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await
            .unwrap()
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    let code = seq_test_client
        .eth_get_code(
            contract_address,
            Some(BlockId::Number(BlockNumberOrTag::Number(9))),
        )
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    let block_hash_9 = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );

    let code = seq_test_client
        .eth_get_code(contract_address, Some(BlockId::Hash(block_hash_9.into())))
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    let block_hash_8 = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(8)))
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );

    let non_existent_code = seq_test_client
        .eth_get_code(contract_address, Some(BlockId::Hash(block_hash_8.into())))
        .await
        .unwrap();
    assert_eq!(non_existent_code, Bytes::from(vec![]));

    let non_existent_code = seq_test_client
        .eth_get_code(
            contract_address,
            Some(BlockId::Number(BlockNumberOrTag::Number(8))),
        )
        .await
        .unwrap();
    assert_eq!(non_existent_code, Bytes::from(vec![]));

    let set_arg = 923;
    seq_test_client
        .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
        .await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    let storage_slot = 0x0;
    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot.into(),
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
        )
        .await
        .unwrap();
    assert_eq!(storage_value, ethereum_types::U256::from(set_arg));

    let latest_block_hash = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(None)
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );

    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot.into(),
            Some(BlockId::Hash(latest_block_hash.into())),
        )
        .await
        .unwrap();
    assert_eq!(storage_value, ethereum_types::U256::from(set_arg));

    let previous_storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot.into(),
            Some(BlockId::Number(BlockNumberOrTag::Number(11))),
        )
        .await
        .unwrap();

    assert_eq!(previous_storage_value, ethereum_types::U256::from(0));

    let block_hash_11 = B256::from_slice(
        seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(11)))
            .await
            .hash
            .unwrap()
            .as_bytes(),
    );

    let previous_storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            storage_slot.into(),
            Some(BlockId::Hash(block_hash_11.into())),
        )
        .await
        .unwrap();

    assert_eq!(previous_storage_value, ethereum_types::U256::from(0));
}
