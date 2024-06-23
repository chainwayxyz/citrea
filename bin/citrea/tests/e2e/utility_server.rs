use citrea_stf::genesis_config::GenesisPaths;
use tokio::time::sleep;

use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT};

#[tokio::test]
async fn test_close_and_reopen_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let (seq_util_port_tx, seq_util_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            Some(seq_util_port_tx),
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(false),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_util_port = seq_util_port_rx.await.unwrap();

    // wait a couple of blocks
    sleep(tokio::time::Duration::from_secs(4)).await;

    //create htttp client with seq_util_port and reqwest
    let health_endpoint = format!(
        "http://{}:{}/health",
        seq_util_port.ip(),
        seq_util_port.port(),
    );
    let resp = reqwest::get(health_endpoint).await?;
    assert_eq!(resp.status(), 200);

    let (full_node_port_tx, _) = tokio::sync::oneshot::channel();
    let (full_node_util_port_tx, full_node_util_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let fullnode_db_dir_cloned = fullnode_db_dir.clone();
    // starting full node with db path
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            Some(full_node_util_port_tx),
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir_cloned,
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

    let full_node_util_port = full_node_util_port_rx.await.unwrap();

    // wait a couple of blocks
    sleep(tokio::time::Duration::from_secs(4)).await;

    //create htttp client with seq_util_port and reqwest
    let health_endpoint = format!(
        "http://{}:{}/health",
        full_node_util_port.ip(),
        full_node_util_port.port(),
    );
    let resp = reqwest::get(health_endpoint).await?;
    assert_eq!(resp.status(), 200);

    seq_task.abort();
    rollup_task.abort();
    Ok(())
}
