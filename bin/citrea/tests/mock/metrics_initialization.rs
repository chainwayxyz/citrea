use std::time::Duration;

use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use serial_test::serial;
use sov_db::ledger_db::migrations::copy_db_dir_recursive;
use sov_mock_da::{MockAddress, MockDaService};
use tokio::time::sleep;

use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_commitment,
    wait_for_l1_block, wait_for_l2_block, wait_for_proof, wait_for_prover_job,
    wait_for_prover_job_count, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

const METRICS_PORT: u16 = 9100;

async fn fetch_metrics() -> anyhow::Result<String> {
    let url = format!("http://127.0.0.1:{}/metrics", METRICS_PORT);
    let response = reqwest::get(&url).await?;
    Ok(response.text().await?)
}

fn extract_metric_value(metrics: &str, metric_name: &str) -> Option<u64> {
    for line in metrics.lines() {
        if line.starts_with(metric_name) && !line.starts_with('#') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_sequencer_metrics_initialization() {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let sequencer_config = SequencerConfig::default();
    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config.clone(),
        Some(sequencer_config.clone()),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    for _ in 0..5 {
        test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&test_client, 5, None).await;

    sleep(Duration::from_secs(2)).await;

    let block_number = test_client.ledger_get_head_l2_block_height().await.unwrap();
    assert_eq!(block_number, 5);

    let metrics = fetch_metrics().await.unwrap();
    let l2_height = extract_metric_value(&metrics, "sequencer_current_l2_block");
    assert_eq!(
        l2_height,
        Some(block_number),
        "L2 height metric should match ledger"
    );

    let commitment_index =
        extract_metric_value(&metrics, "sequencer_latest_sequencer_commitment_index");
    let commitment_end_height = extract_metric_value(
        &metrics,
        "sequencer_latest_sequencer_commitment_l2_end_height",
    );
    assert_eq!(commitment_index, Some(1), "Commitment index should be 1");
    assert_eq!(
        commitment_end_height,
        Some(4),
        "Commitment end height should be 4"
    );

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    seq_task.graceful_shutdown();

    let sequencer_db_dir_new = storage_dir.path().join("sequencer_restart").to_path_buf();
    copy_db_dir_recursive(&sequencer_db_dir, &sequencer_db_dir_new).unwrap();

    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir_new,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
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
    let test_client = make_test_client(seq_port).await.unwrap();

    sleep(Duration::from_secs(2)).await;

    let block_number = test_client.ledger_get_head_l2_block_height().await.unwrap();
    assert_eq!(block_number, 5);

    let metrics = fetch_metrics().await.unwrap();
    let l2_height = extract_metric_value(&metrics, "sequencer_current_l2_block");
    assert_eq!(
        l2_height,
        Some(block_number),
        "L2 height metric should match ledger after restart"
    );

    let commitment_index =
        extract_metric_value(&metrics, "sequencer_latest_sequencer_commitment_index");
    let commitment_end_height = extract_metric_value(
        &metrics,
        "sequencer_latest_sequencer_commitment_l2_end_height",
    );
    assert_eq!(
        commitment_index,
        Some(1),
        "Commitment index should be 1 after restart"
    );
    assert_eq!(
        commitment_end_height,
        Some(4),
        "Commitment end height should be 4 after restart"
    );

    seq_task.graceful_shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_fullnode_metrics_initialization() {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "fullnode"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("fullnode").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let sequencer_config = SequencerConfig::default();
    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );

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

    let (fullnode_port_tx, fullnode_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let fullnode_task = start_rollup(
        fullnode_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let fullnode_port = fullnode_port_rx.await.unwrap();
    let fullnode_client = make_test_client(fullnode_port).await.unwrap();

    let test_client = make_test_client(seq_port).await.unwrap();
    for _ in 0..4 {
        test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&fullnode_client, 4, None).await;

    sleep(Duration::from_secs(2)).await;

    let block_number = fullnode_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();
    assert_eq!(block_number, 4);

    let metrics = fetch_metrics().await.unwrap();
    let l2_height = extract_metric_value(&metrics, "fullnode_current_l2_block");
    assert_eq!(
        l2_height,
        Some(block_number),
        "Fullnode L2 height metric should match ledger"
    );

    let committed_height = extract_metric_value(&metrics, "fullnode_highest_committed_l2_height");
    let committed_index = extract_metric_value(&metrics, "fullnode_highest_committed_index");
    assert_eq!(
        committed_height,
        Some(4),
        "Fullnode highest committed L2 height should be 4"
    );
    assert_eq!(
        committed_index,
        Some(1),
        "Fullnode highest committed index should be 1"
    );

    fullnode_task.graceful_shutdown();

    let fullnode_db_dir_new = storage_dir.path().join("fullnode_restart").to_path_buf();
    copy_db_dir_recursive(&fullnode_db_dir, &fullnode_db_dir_new).unwrap();

    let (fullnode_port_tx, fullnode_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir_new,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let fullnode_task = start_rollup(
        fullnode_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let fullnode_port = fullnode_port_rx.await.unwrap();
    let fullnode_client = make_test_client(fullnode_port).await.unwrap();

    sleep(Duration::from_secs(2)).await;

    let block_number = fullnode_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();
    assert_eq!(block_number, 4);

    let metrics = fetch_metrics().await.unwrap();
    let l2_height = extract_metric_value(&metrics, "fullnode_current_l2_block");
    assert_eq!(
        l2_height,
        Some(block_number),
        "Fullnode L2 height metric should match ledger after restart"
    );

    let committed_height = extract_metric_value(&metrics, "fullnode_highest_committed_l2_height");
    let committed_index = extract_metric_value(&metrics, "fullnode_highest_committed_index");
    assert_eq!(
        committed_height,
        Some(4),
        "Fullnode highest committed L2 height should be 4 after restart"
    );
    assert_eq!(
        committed_index,
        Some(1),
        "Fullnode highest committed index should be 1 after restart"
    );

    seq_task.graceful_shutdown();
    fullnode_task.graceful_shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_all_nodes_metrics_initialization() {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "fullnode"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("fullnode").to_path_buf();

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let sequencer_config = SequencerConfig::default();
    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

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
    let seq_client = make_test_client(seq_port).await.unwrap();

    let (prover_port_tx, prover_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &prover_db_dir,
        &da_db_dir,
        NodeMode::Prover(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let prover_task = start_rollup(
        prover_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        Some(citrea_common::BatchProverConfig {
            proving_mode: citrea_common::ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
            max_commitments_per_proof: None,
        }),
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let prover_port = prover_port_rx.await.unwrap();
    let prover_client = make_test_client(prover_port).await.unwrap();

    let (fullnode_port_tx, fullnode_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let fullnode_task = start_rollup(
        fullnode_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let fullnode_port = fullnode_port_rx.await.unwrap();
    let fullnode_client = make_test_client(fullnode_port).await.unwrap();

    seq_client.send_publish_batch_request().await;
    seq_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_client, 2, None).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    seq_client.send_publish_batch_request().await;
    seq_client.send_publish_batch_request().await;

    wait_for_l2_block(&seq_client, 4, None).await;
    wait_for_l2_block(&prover_client, 4, None).await;
    wait_for_l2_block(&fullnode_client, 4, None).await;

    let commitments = wait_for_commitment(&da_service, 3, None).await;
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    let job_ids = wait_for_prover_job_count(&prover_client, 1, None)
        .await
        .unwrap();
    assert_eq!(job_ids.len(), 1);
    let _response = wait_for_prover_job(&prover_client, job_ids[0], None)
        .await
        .unwrap();

    wait_for_l1_block(&da_service, 4, None).await;

    for i in 5..=6 {
        seq_client.send_publish_batch_request().await;
        wait_for_l2_block(&fullnode_client, i, None).await;
    }

    wait_for_proof(&fullnode_client, 4, Some(Duration::from_secs(60))).await;

    sleep(Duration::from_secs(2)).await;

    let seq_block = seq_client.ledger_get_head_l2_block_height().await.unwrap();
    let prover_block = prover_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();
    let fullnode_block = fullnode_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();

    assert_eq!(seq_block, prover_block);
    assert_eq!(seq_block, fullnode_block);
    assert!(
        seq_block >= 6,
        "Expected at least 6 blocks, got {}",
        seq_block
    );

    sleep(Duration::from_secs(2)).await;

    let metrics = fetch_metrics().await.unwrap();

    let seq_l2_height = extract_metric_value(&metrics, "sequencer_current_l2_block");
    let prover_l2_height = extract_metric_value(&metrics, "batch_prover_current_l2_block");
    let fullnode_l2_height = extract_metric_value(&metrics, "fullnode_current_l2_block");

    assert_eq!(
        seq_l2_height,
        Some(seq_block),
        "Sequencer L2 height metric should match ledger"
    );
    assert_eq!(
        prover_l2_height,
        Some(prover_block),
        "Prover L2 height metric should match ledger"
    );
    assert_eq!(
        fullnode_l2_height,
        Some(fullnode_block),
        "Fullnode L2 height metric should match ledger"
    );

    let prover_l1_height = extract_metric_value(&metrics, "batch_prover_current_l1_block");
    assert!(
        matches!(prover_l1_height, Some(h) if h >= 1),
        "Prover L1 height metric should be at least 1 (genesis block), got {:?}",
        prover_l1_height
    );

    let commitment_index =
        extract_metric_value(&metrics, "sequencer_latest_sequencer_commitment_index");
    let commitment_end_height = extract_metric_value(
        &metrics,
        "sequencer_latest_sequencer_commitment_l2_end_height",
    );
    assert_eq!(commitment_index, Some(1), "Commitment index should be 1");
    assert_eq!(
        commitment_end_height,
        Some(4),
        "Commitment end height should be 4"
    );

    let fullnode_committed_height =
        extract_metric_value(&metrics, "fullnode_highest_committed_l2_height");
    let fullnode_committed_index =
        extract_metric_value(&metrics, "fullnode_highest_committed_index");
    let fullnode_proven_height =
        extract_metric_value(&metrics, "fullnode_highest_proven_l2_height");
    assert_eq!(
        fullnode_committed_height,
        Some(4),
        "Fullnode highest committed L2 height should be 4"
    );
    assert_eq!(
        fullnode_committed_index,
        Some(1),
        "Fullnode highest committed index should be 1"
    );
    assert_eq!(
        fullnode_proven_height,
        Some(4),
        "Fullnode highest proven L2 height should be 4 after proof verification"
    );

    seq_task.graceful_shutdown();
    prover_task.graceful_shutdown();
    fullnode_task.graceful_shutdown();

    let sequencer_db_dir_new = storage_dir.path().join("sequencer_restart").to_path_buf();
    let prover_db_dir_new = storage_dir.path().join("prover_restart").to_path_buf();
    let fullnode_db_dir_new = storage_dir.path().join("fullnode_restart").to_path_buf();

    copy_db_dir_recursive(&sequencer_db_dir, &sequencer_db_dir_new).unwrap();
    copy_db_dir_recursive(&prover_db_dir, &prover_db_dir_new).unwrap();
    copy_db_dir_recursive(&fullnode_db_dir, &fullnode_db_dir_new).unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let sequencer_config = SequencerConfig::default();
    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir_new,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

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
    let seq_client = make_test_client(seq_port).await.unwrap();

    let (prover_port_tx, prover_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &prover_db_dir_new,
        &da_db_dir,
        NodeMode::Prover(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let prover_task = start_rollup(
        prover_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        Some(citrea_common::BatchProverConfig {
            proving_mode: citrea_common::ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
            max_commitments_per_proof: None,
        }),
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let prover_port = prover_port_rx.await.unwrap();
    let prover_client = make_test_client(prover_port).await.unwrap();

    let (fullnode_port_tx, fullnode_port_rx) = tokio::sync::oneshot::channel();
    let mut rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir_new,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    rollup_config.telemetry.bind_host = Some("127.0.0.1".to_string());
    rollup_config.telemetry.bind_port = Some(METRICS_PORT);

    let fullnode_task = start_rollup(
        fullnode_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let fullnode_port = fullnode_port_rx.await.unwrap();
    let fullnode_client = make_test_client(fullnode_port).await.unwrap();

    let seq_block = seq_client.ledger_get_head_l2_block_height().await.unwrap();
    let prover_block = prover_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();
    let fullnode_block = fullnode_client
        .ledger_get_head_l2_block_height()
        .await
        .unwrap();

    assert_eq!(seq_block, prover_block);
    assert_eq!(seq_block, fullnode_block);
    assert!(
        seq_block >= 6,
        "Expected at least 6 blocks after restart, got {}",
        seq_block
    );

    sleep(Duration::from_secs(3)).await;

    let metrics = fetch_metrics().await.unwrap();

    let seq_l2_height = extract_metric_value(&metrics, "sequencer_current_l2_block");
    let prover_l2_height = extract_metric_value(&metrics, "batch_prover_current_l2_block");
    let fullnode_l2_height = extract_metric_value(&metrics, "fullnode_current_l2_block");

    assert_eq!(
        seq_l2_height,
        Some(seq_block),
        "Sequencer L2 height metric should match ledger after restart"
    );
    assert_eq!(
        prover_l2_height,
        Some(prover_block),
        "Prover L2 height metric should match ledger after restart"
    );
    assert_eq!(
        fullnode_l2_height,
        Some(fullnode_block),
        "Fullnode L2 height metric should match ledger after restart"
    );

    let prover_l1_height = extract_metric_value(&metrics, "batch_prover_current_l1_block");
    assert!(
        matches!(prover_l1_height, Some(h) if h >= 1),
        "Prover L1 height metric should be at least 1 (genesis block) after restart, got {:?}",
        prover_l1_height
    );

    let commitment_index =
        extract_metric_value(&metrics, "sequencer_latest_sequencer_commitment_index");
    let commitment_end_height = extract_metric_value(
        &metrics,
        "sequencer_latest_sequencer_commitment_l2_end_height",
    );
    assert_eq!(
        commitment_index,
        Some(1),
        "Commitment index should be 1 after restart"
    );
    assert_eq!(
        commitment_end_height,
        Some(4),
        "Commitment end height should be 4 after restart"
    );

    let fullnode_committed_height =
        extract_metric_value(&metrics, "fullnode_highest_committed_l2_height");
    let fullnode_committed_index =
        extract_metric_value(&metrics, "fullnode_highest_committed_index");
    let fullnode_proven_height =
        extract_metric_value(&metrics, "fullnode_highest_proven_l2_height");
    assert_eq!(
        fullnode_committed_height,
        Some(4),
        "Fullnode highest committed L2 height should be 4 after restart"
    );
    assert_eq!(
        fullnode_committed_index,
        Some(1),
        "Fullnode highest committed index should be 1 after restart"
    );
    assert_eq!(
        fullnode_proven_height,
        Some(4),
        "Fullnode highest proven L2 height should be 4 after restart (persisted)"
    );

    seq_task.graceful_shutdown();
    prover_task.graceful_shutdown();
    fullnode_task.graceful_shutdown();
}
