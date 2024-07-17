use std::str::FromStr;
use std::time::Duration;

use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag, Bytes, U256};
use tokio::time::sleep;

use crate::evm::init_test_rollup;
use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_archival_state() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
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
    let invalid_block_balance = seq_test_client
        .eth_get_balance(addr, Some(BlockNumberOrTag::Number(722)))
        .await
        .unwrap_err();

    assert!(invalid_block_balance
        .to_string()
        .contains("unknown block number"));

    let invalid_block_storage = seq_test_client
        .eth_get_storage_at(addr, U256::from(0), Some(BlockNumberOrTag::Number(722)))
        .await
        .unwrap_err();
    assert!(invalid_block_storage
        .to_string()
        .contains("unknown block number"));

    let invalid_block_code = seq_test_client
        .eth_get_code(addr, Some(BlockNumberOrTag::Number(722)))
        .await
        .unwrap_err();
    assert!(invalid_block_code
        .to_string()
        .contains("unknown block number"));

    let invalid_block_tx_count = seq_test_client
        .eth_get_transaction_count(addr, Some(BlockNumberOrTag::Number(722)))
        .await
        .unwrap_err();
    assert!(invalid_block_tx_count
        .to_string()
        .contains("unknown block number"));
}

async fn run_archival_valid_tests(addr: Address, seq_test_client: &TestClient) {
    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockNumberOrTag::Latest))
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_storage_at(addr, U256::from(0), Some(BlockNumberOrTag::Latest))
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockNumberOrTag::Latest))
            .await
            .unwrap(),
        Bytes::from([])
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(addr, Some(BlockNumberOrTag::Latest))
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
    wait_for_l2_block(seq_test_client, 8, None).await;

    // Wait for changeset storage
    sleep(Duration::from_secs(2)).await;

    assert_eq!(
        seq_test_client
            .eth_get_balance(addr, Some(BlockNumberOrTag::Latest))
            .await
            .unwrap(),
        U256::from(8)
    );

    assert_eq!(
        seq_test_client.eth_get_balance(addr, None).await.unwrap(),
        U256::from(8)
    );

    assert_eq!(
        seq_test_client
            .eth_get_transaction_count(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockNumberOrTag::Latest)
            )
            .await
            .unwrap(),
        8
    );

    for i in 1..8 {
        assert_eq!(
            seq_test_client
                .eth_get_balance(addr, Some(BlockNumberOrTag::Number(i)))
                .await
                .unwrap(),
            U256::from(i)
        );

        assert_eq!(
            seq_test_client
                .eth_get_transaction_count(
                    Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                    Some(BlockNumberOrTag::Number(i))
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
                U256::from(0),
                Some(BlockNumberOrTag::Latest)
            )
            .await
            .unwrap(),
        U256::from(0)
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(addr, Some(BlockNumberOrTag::Latest))
            .await
            .unwrap(),
        Bytes::from(vec![])
    );

    assert_eq!(
        seq_test_client
            .eth_get_code(
                Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
                Some(BlockNumberOrTag::Latest)
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
        wait_for_l2_block(seq_test_client, 9, None).await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(seq_test_client, 11, None).await;

    let code = seq_test_client
        .eth_get_code(contract_address, Some(BlockNumberOrTag::Number(9)))
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    let non_existent_code = seq_test_client
        .eth_get_code(contract_address, Some(BlockNumberOrTag::Number(8)))
        .await
        .unwrap();
    assert_eq!(non_existent_code, Bytes::from(vec![]));

    let set_arg = 923;
    let _pending = seq_test_client
        .contract_transaction(contract_address, contract.set_call_data(set_arg), None)
        .await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(seq_test_client, 13, None).await;

    let storage_slot = 0x0;
    let storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            U256::from(storage_slot),
            Some(BlockNumberOrTag::Latest),
        )
        .await
        .unwrap();
    assert_eq!(storage_value, U256::from(set_arg));

    let previous_storage_value = seq_test_client
        .eth_get_storage_at(
            contract_address,
            U256::from(storage_slot),
            Some(BlockNumberOrTag::Number(11)),
        )
        .await
        .unwrap();

    assert_eq!(previous_storage_value, U256::from(0));
}
