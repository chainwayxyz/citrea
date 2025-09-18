/// Testing pending block functionality with mempool transactions
use alloy_rpc_types::BlockNumberOrTag;
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;

use super::evm::init_test_rollup;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::TEST_DATA_GENESIS_PATH;

/// Test that pending block returns valid block when queried from sequencer
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_pending_block() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );

    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: 1000,
        da_update_interval_ms: 500,
        block_production_interval_ms: 2,
        ..Default::default()
    };

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }

    let latest_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let latest_block_number = latest_block.header.number;

    let pending_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Pending))
        .await;

    assert_eq!(pending_block.header.number, latest_block_number + 1);

    seq_task.graceful_shutdown();
    Ok(())
}

/// Test that pending block returns valid block when queried from fullnode
#[tokio::test(flavor = "multi_thread")]
async fn test_fullnode_pending_block() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "fullnode"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("fullnode").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let seq_rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );

    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: 1000,
        da_update_interval_ms: 500,
        block_production_interval_ms: 2,
        ..Default::default()
    };

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        seq_rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }

    // Start fullnode
    let fullnode_rollup_config = create_default_rollup_config(
        false,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );

    let full_node_task = start_rollup(
        full_node_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        fullnode_rollup_config,
        None,
        None,
        false,
    )
    .await;

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = init_test_rollup(full_node_port).await;

    wait_for_l2_block(&full_node_test_client, 3, None).await;

    // Get latest block from fullnode
    let latest_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let latest_block_number = latest_block.header.number;

    let pending_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Pending))
        .await;

    assert_eq!(pending_block.header.number, latest_block_number + 1);

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();
    Ok(())
}
