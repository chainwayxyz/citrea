use std::time::Duration;

use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::L2BlockStatus;
use tokio::time::sleep;

use super::{initialize_test, TestConfig};
use crate::common::helpers::{tempdir_with_children, wait_for_l1_block, wait_for_l2_block};

/// Run the sequencer and full node.
/// Trigger sequencer commitments.
/// Check if the full node finds sequencer commitments on DA blocks. Then
/// check if the full node correctly marks the l2 blocks.
/// Do this for a single L1 block.
#[tokio::test(flavor = "multi_thread")]
async fn test_l2_blocks_status_one_l1() -> Result<(), anyhow::Error> {
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
            seq_max_l2_blocks: 3,
            deposit_mempool_fetch_limit: 10,
            pruning_config: None,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // now retrieve l2 block status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_l2_block_status(i)
            .await
            .unwrap();

        assert_eq!(L2BlockStatus::Trusted, status_node);
    }

    // Wait for DA block #2 containing the commitment
    // submitted by sequencer.
    wait_for_l1_block(&da_service, 2, None).await;
    // wait for full node to process the DA block
    sleep(Duration::from_secs(10)).await;

    // now retrieve l2 block status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_l2_block_status(i)
            .await
            .unwrap();

        assert_eq!(L2BlockStatus::Finalized, status_node);
    }

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

/// Run the sequencer and full node.
/// Trigger sequencer commitments.
/// Check if the full node finds sequencer commitments on DA blocks. Then
/// check if the full node correctly marks the l2 blocks.
/// Do this for two L1 blocks.
#[tokio::test(flavor = "multi_thread")]
async fn test_l2_blocks_status_two_l1() -> Result<(), anyhow::Error> {
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
            seq_max_l2_blocks: 3,
            deposit_mempool_fetch_limit: 10,
            ..Default::default()
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

    // now retrieve l2 block status from the sequencer and full node and check if they are the same
    for i in 1..=3 {
        let status_node = full_node_test_client
            .ledger_get_l2_block_status(i)
            .await
            .unwrap();

        assert_eq!(L2BlockStatus::Finalized, status_node);
    }

    // now retrieve l2 block status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_l2_block_status(i)
            .await
            .unwrap();

        assert_eq!(L2BlockStatus::Finalized, status_node);
    }

    let status_node = full_node_test_client.ledger_get_l2_block_status(410).await;

    assert!(
        format!("{:?}", status_node.err()).contains("L2 block at height 410 not processed yet.")
    );

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}
