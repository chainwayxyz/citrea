use std::panic::AssertUnwindSafe;

/// Testing if the sequencer and full node can handle system transactions correctly (the full node should have the same system transactions as the sequencer)
use citrea_pruning::PruningConfig;
use futures::FutureExt;
use reth_primitives::BlockNumberOrTag;
use sov_mock_da::{MockAddress, MockDaService};

use crate::e2e::{initialize_test, TestConfig};
use crate::test_helpers::{tempdir_with_children, wait_for_l1_block, wait_for_l2_block};

/// Trigger pruning native DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_native_db_pruning() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            pruning_config: Some(PruningConfig { distance: 20 }),
            ..Default::default()
        })
        .await;

    for i in 0..10 {
        for _ in 0..5 {
            seq_test_client.spam_publish_batch_request().await.unwrap();
        }
        wait_for_l2_block(&seq_test_client, 5 * (i + 1), None).await;

        da_service.publish_test_block().await.unwrap();

        wait_for_l1_block(&da_service, 4 + i, None).await;
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 51, None).await;

    // This request is requesting data which has been pruned.
    let panic_1 = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(1))),
    )
    .catch_unwind()
    .await;
    assert!(panic_1.is_err());

    // This request is requesting data which has been pruned.
    let panic_2 = AssertUnwindSafe(
        full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(20))),
    )
    .catch_unwind()
    .await;
    assert!(panic_2.is_err());

    // Should NOT panic as the data we're requesting here is correct
    full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(21)))
        .await;

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}
