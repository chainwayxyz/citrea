/// In case of a sequencer crash, the runner of the sequencer can replace it one of the full nodes they also run.
/// This feature is useful for high availability.
/// However, there is certain problems that come with it and this feature is subject to be removed in the future.
use alloy_rpc_types::BlockNumberOrTag;
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;

use super::evm::init_test_rollup;
use super::{execute_blocks, TestConfig};
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

/// Run the sequencer and the full node.
/// Check if the full node saves and serves the l2 blocks by
/// starting a new full node that syncs from the first full node.
#[tokio::test(flavor = "multi_thread")]
async fn test_l2_block_save() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let fullnode2_db_dir = storage_dir.path().join("full-node2").to_path_buf();

    let config = TestConfig {
        da_path: da_db_dir.clone(),
        sequencer_path: sequencer_db_dir.clone(),
        fullnode_path: fullnode_db_dir.clone(),
        ..Default::default()
    };

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: config.seq_max_l2_blocks,
        deposit_mempool_fetch_limit: config.deposit_mempool_fetch_limit,
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

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
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
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await?;

    let (full_node_port_tx_2, full_node_port_rx_2) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        false,
        &fullnode2_db_dir,
        &da_db_dir,
        NodeMode::FullNode(full_node_port),
        None,
    );
    let full_node_task_2 = start_rollup(
        full_node_port_tx_2,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let full_node_port_2 = full_node_port_rx_2.await.unwrap();
    let full_node_test_client_2 = make_test_client(full_node_port_2).await?;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client, &da_db_dir.clone()).await;

    wait_for_l2_block(&full_node_test_client_2, 504, None).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let full_node_block_2 = full_node_test_client_2
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        seq_block.header.state_root,
        full_node_block.header.state_root
    );
    assert_eq!(
        full_node_block.header.state_root,
        full_node_block_2.header.state_root
    );
    assert_eq!(seq_block.header.hash, full_node_block.header.hash);
    assert_eq!(full_node_block.header.hash, full_node_block_2.header.hash);

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();
    full_node_task_2.graceful_shutdown();

    Ok(())
}
