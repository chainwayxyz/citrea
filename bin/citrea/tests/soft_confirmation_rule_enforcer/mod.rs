use citrea_stf::genesis_config::GenesisPaths;
use sov_mock_da::{MockAddress, MockDaService};

use crate::evm::make_test_client;
// use citrea::initialize_logging;
use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT};

/// Transaction with equal nonce to last tx should not be accepted by mempool.
#[tokio::test(flavor = "multi_thread")]
async fn too_many_l2_block_per_l1_block() {
    // citrea::initialize_logging();

    let storage_dir = tempdir_with_children(&vec!["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests-low-limiting-number"),
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
    let test_client = make_test_client(seq_port).await;
    let limiting_number = test_client.get_limiting_number().await;

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    // limiting number should be 10
    // we use a low limiting number because mockda creates blocks every 5 seconds
    // and we want to test the error in a reasonable time
    assert_eq!(limiting_number, 10);

    // create 2*limiting_number + 1 blocks so it has to give error
    for idx in 0..2 * limiting_number + 1 {
        test_client.spam_publish_batch_request().await.unwrap();
        if idx >= limiting_number {
            // There should not be any more blocks published from this point
            // because the limiting number is reached
            assert_eq!(test_client.eth_block_number().await, 10);
        }
    }
    let mut last_block_number = test_client.eth_block_number().await;

    da_service.publish_test_block().await.unwrap();

    for idx in 0..2 * limiting_number + 1 {
        test_client.spam_publish_batch_request().await.unwrap();
        if idx < limiting_number {
            assert_eq!(test_client.eth_block_number().await, last_block_number + 1);
        }
        last_block_number += 1;
        if idx >= limiting_number {
            // There should not be any more blocks published from this point
            // because the limiting number is reached again
            assert_eq!(test_client.eth_block_number().await, 20);
        }
    }
}
