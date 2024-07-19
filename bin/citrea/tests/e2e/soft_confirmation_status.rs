use std::str::FromStr;
use std::time::Duration;

use citrea_stf::genesis_config::GenesisPaths;
use ethereum_rpc::CitreaStatus;
use reth_primitives::Address;
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_rollup_interface::rpc::SoftConfirmationStatus;

use crate::e2e::{initialize_test, TestConfig};
use crate::evm::{init_test_rollup, make_test_client};
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_status_one_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir);

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Trusted, status_node.unwrap());
    }

    // Wait for DA block #2 containing the commitment
    // submitted by sequencer.
    wait_for_l1_block(&da_service, 2, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Finalized, status_node.unwrap());
    }

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_status_two_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=3 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 3, None).await;
    // L2 blocks 1-3 would create an L1 block with commitment
    wait_for_l1_block(&da_service, 2, None).await;

    for _ in 4..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&full_node_test_client, 6, None).await;
    // L2 blocks 4-6 would create an L1 block with commitment
    wait_for_l1_block(&da_service, 3, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=3 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Finalized, status_node.unwrap());
    }

    // Check that these L2 blocks are bounded on different L1 block
    let mut batch_infos = vec![];
    for i in 1..=6 {
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        batch_infos.push(full_node_soft_conf);
    }

    // First three blocks got created on L1 height 1.
    assert!(batch_infos[0..3]
        .iter()
        .all(|x| { x.da_slot_height == batch_infos[0].da_slot_height }));

    // Blocks 4, 5, 6 were created on L1 height 2
    assert!(batch_infos[3..6]
        .iter()
        .all(|x| { x.da_slot_height == batch_infos[3].da_slot_height }));
    assert_ne!(batch_infos[0].da_slot_height, batch_infos[5].da_slot_height);

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Finalized, status_node.unwrap());
    }

    let status_node = full_node_test_client
        .ledger_get_soft_confirmation_status(410)
        .await;

    assert!(format!("{:?}", status_node.err())
        .contains("Soft confirmation at height 410 not processed yet."));

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_full_node_sync_status() {
    // citrea::initialize_logging();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

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
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..300 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 300, Some(Duration::from_secs(60))).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
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

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    wait_for_l2_block(&full_node_test_client, 5, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Syncing(syncing) => {
            assert!(syncing.synced_block_number > 0 && syncing.synced_block_number < 300);
            assert_eq!(syncing.head_block_number, 300);
        }
        _ => panic!("Expected syncing status"),
    }

    wait_for_l2_block(&full_node_test_client, 300, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Synced(synced_up_to) => assert_eq!(synced_up_to, 300),
        _ => panic!("Expected synced status"),
    }

    seq_task.abort();
    full_node_task.abort();
}
