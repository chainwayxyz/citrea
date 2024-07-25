use sov_mock_da::{MockAddress, MockDaService, MockDaSpec};
use sov_rollup_interface::rpc::SoftConfirmationStatus;

use crate::e2e::{initialize_test, TestConfig};
use crate::test_helpers::{tempdir_with_children, wait_for_l1_block, wait_for_l2_block};

/// Run the sequencer and full node.
/// Trigger sequencer commitments.
/// Check if the full node finds sequencer commitments on DA blocks. Then
/// check if the full node correctly marks the soft confirmations.
/// Do this for a single L1 block.
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

/// Run the sequencer and full node.
/// Trigger sequencer commitments.
/// Check if the full node finds sequencer commitments on DA blocks. Then
/// check if the full node correctly marks the soft confirmations.
/// Do this for two L1 blocks.
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
