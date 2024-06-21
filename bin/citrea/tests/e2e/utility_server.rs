use citrea_stf::genesis_config::GenesisPaths;
use sov_stf_runner::ProverConfig;

use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    DEFAULT_PROOF_WAIT_DURATION,
};

#[tokio::test]
async fn test_close_and_reopen_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();

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
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_util_port = seq_util_port_rx.await.unwrap();

    //create htttp client with seq_util_port and reqwest
    let health_endpoint = format!(
        "http://{}:{}/health",
        seq_util_port.ip(),
        seq_util_port.port(),
    );
    let resp = reqwest::get(health_endpoint).await?;
    assert_eq!(resp.status(), 200);

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();
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

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_util_port = full_node_util_port_rx.await.unwrap();

    //create htttp client with seq_util_port and reqwest
    let health_endpoint = format!(
        "http://{}:{}/health",
        full_node_util_port.ip(),
        full_node_util_port.port(),
    );
    let resp = reqwest::get(health_endpoint).await?;
    assert_eq!(resp.status(), 200);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();
    let (prover_node_util_port_tx, prover_node_util_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            Some(prover_node_util_port_tx),
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                db_config: Some(Default::default()),
                proof_sampling_number: 0,
            }),
            NodeMode::Prover(seq_port),
            prover_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();
    let prover_node_util_port = prover_node_util_port_rx.await.unwrap();

    //create htttp client with seq_util_port and reqwest
    let health_endpoint = format!(
        "http://{}:{}/health",
        prover_node_util_port.ip(),
        prover_node_util_port.port(),
    );
    let resp = reqwest::get(health_endpoint).await?;
    assert_eq!(resp.status(), 200);

    seq_task.abort();
    rollup_task.abort();
    prover_node_task.abort();
    Ok(())
}
//cargo test --package citrea --test all_tests --all-features -- e2e::utility_server::test_close_and_reopen_full_node --exact --show-output
