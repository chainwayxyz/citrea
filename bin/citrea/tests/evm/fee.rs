// use citrea::initialize_logging;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::BlockNumberOrTag;

// use sov_demo_rollup::initialize_logging;
use crate::evm::init_test_rollup;
use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_minimum_base_fee() -> Result<(), anyhow::Error> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let _ = tokio::spawn(async move {
        // Don't provide a prover since the EVM is not currently provable
        start_rollup(
            port_tx,
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

    // Wait for rollup task to start:
    let port = port_rx.await.unwrap();
    let test_client = init_test_rollup(port).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    assert!(block.header.base_fee_per_gas.unwrap() >= 10000000);
    for _ in 0..100 {
        test_client.spam_publish_batch_request().await.unwrap();
    }

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    // Base fee should at most be 0.01 gwei
    assert!(block.header.base_fee_per_gas.unwrap() >= 10000000);

    Ok(())
}
