use std::time::Duration;

use citrea_sequencer::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use sov_mock_da::{MockAddress, MockDaService};
use tokio::time::sleep;

use crate::evm::make_test_client;
// use citrea::initialize_logging;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, NodeMode,
};
use crate::TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT;

/// Transaction with equal nonce to last tx should not be accepted by mempool.
#[tokio::test(flavor = "multi_thread")]
async fn too_many_l2_block_per_l1_block() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir_cloned,
        NodeMode::SequencerNode,
    );
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment:
            TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
        ..Default::default()
    };
    tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(
                "../../resources/test-data/integration-tests-low-max-l2-blocks-per-l1",
            ),
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });
    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();
    let max_l2_blocks_per_l1 = test_client.get_max_l2_blocks_per_l1().await;

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    // max L2 blocks per L1 should be 10
    // we use a low max L2 blocks per L1 because mockda creates blocks every 5 seconds
    // and we want to test the error in a reasonable time
    assert_eq!(max_l2_blocks_per_l1, 10);

    // create 2*max_l2_blocks_per_l1 + 1 blocks so it has to give error
    for idx in 0..2 * max_l2_blocks_per_l1 + 1 {
        test_client.spam_publish_batch_request().await.unwrap();
        if idx >= max_l2_blocks_per_l1 {
            // There should not be any more blocks published from this point
            // because the max L2 blocks per L1 is reached
            wait_for_l2_block(&test_client, 10, None).await;
            assert_eq!(test_client.eth_block_number().await, 10);
        }
    }
    let mut last_block_number = test_client.eth_block_number().await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    // Wait for the sequencer DA update interval to pass for it to recognize
    // the new DA block.
    sleep(Duration::from_secs(1)).await;

    for idx in 0..2 * max_l2_blocks_per_l1 + 1 {
        test_client.spam_publish_batch_request().await.unwrap();
        if idx < max_l2_blocks_per_l1 {
            wait_for_l2_block(
                &test_client,
                last_block_number + 1,
                Some(Duration::from_secs(60)),
            )
            .await;
            assert_eq!(test_client.eth_block_number().await, last_block_number + 1);
        }
        last_block_number += 1;
        if idx >= max_l2_blocks_per_l1 {
            // There should not be any more blocks published from this point
            // because the max L2 blocks per L1 is reached again
            wait_for_l2_block(&test_client, 20, None).await;
            assert_eq!(test_client.eth_block_number().await, 20);
        }
    }
}
