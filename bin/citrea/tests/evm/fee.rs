use std::time::Duration;

use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::BlockNumberOrTag;

use crate::evm::init_test_rollup;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn test_minimum_base_fee() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig::default();
    tokio::spawn(async {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();
    let test_client = init_test_rollup(port).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    assert!(block.header.base_fee_per_gas.unwrap() >= 10000000);

    // we used to have 10k here, and the test would finish execution
    // before sequencer was done with all 10k blocks
    // turns out even 1k blocks is enough
    for _ in 0..1600 {
        test_client.spam_publish_batch_request().await.unwrap();
    }

    wait_for_l2_block(&test_client, 1600, Some(Duration::from_secs(90))).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    // Base fee should at most be 0.01 gwei
    assert_eq!(block.header.base_fee_per_gas.unwrap(), 10000000);

    Ok(())
}
