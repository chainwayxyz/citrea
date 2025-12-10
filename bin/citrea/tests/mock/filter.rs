use std::time::Duration;

use alloy_rpc_types::Filter;
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use tokio::time::sleep;

use super::evm::init_test_rollup;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::TEST_DATA_GENESIS_PATH;

#[tokio::test(flavor = "multi_thread")]
async fn test_filter_changes() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    // Update the stale filter TTL to 10 seconds for testing purposes
    rollup_config.rpc.stale_filter_ttl = Some(10);
    // Enable filters for this test
    rollup_config.rpc.enable_filters = true;
    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: 1000,
        da_update_interval_ms: 500,
        block_production_interval_ms: 500,
        ..Default::default()
    };
    let _seq_task = start_rollup(
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

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 3, None).await;

    let filter = Filter::default();
    let filter_id = seq_test_client.install_filter(filter).await.unwrap();
    // Try to remove filter
    let res = seq_test_client
        .uninstall_filter(filter_id.clone())
        .await
        .unwrap();
    // Should be found and removed
    assert!(res);

    // Try to remove again
    let res = seq_test_client.uninstall_filter(filter_id).await.unwrap();
    // Should not be found
    assert!(!res);

    // Create a new filter
    let filter = Filter::default();
    let filter_id = seq_test_client.install_filter(filter).await.unwrap();

    // Wait for 21 seconds (2*ttl+1 second more than the TTL)
    sleep(Duration::from_secs(21)).await;
    // Try to remove filter
    let res = seq_test_client.uninstall_filter(filter_id).await.unwrap();
    // Should not be found as it should be removed due to TTL expiry
    assert!(!res);
    // create a block filter and check it works
    let filter_id = seq_test_client.new_block_filter().await.unwrap();

    // Publish some blocks
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    wait_for_l2_block(&seq_test_client, 8, None).await;

    // Get filter changes
    let changes = seq_test_client.get_filter_changes(filter_id).await.unwrap();

    // It should return 6 blocks, the one at which the filter was created + 5 new ones
    assert_eq!(changes.as_hashes().unwrap().iter().len(), 6);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_filters_disabled() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let mut rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    rollup_config.rpc.enable_filters = false;

    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: 1000,
        da_update_interval_ms: 500,
        block_production_interval_ms: 500,
        ..Default::default()
    };

    let _seq_task = start_rollup(
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

    // Wait for a block to be produced
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 1, None).await;

    // Test that filter RPC methods return "method not found" errors
    let filter = Filter::default();

    let result = seq_test_client.install_filter(filter).await;
    assert!(
        result.is_err(),
        "eth_newFilter should fail when filters are disabled"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Method not found") || err.to_string().contains("-32601"),
        "Expected 'Method not found' error, got: {err}"
    );

    let result = seq_test_client.new_block_filter().await;
    assert!(
        result.is_err(),
        "eth_newBlockFilter should fail when filters are disabled"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Method not found") || err.to_string().contains("-32601"),
        "Expected 'Method not found' error, got: {err}"
    );

    let dummy_filter_id = "0x1".to_string();
    let result = seq_test_client
        .get_filter_changes(dummy_filter_id.clone().into())
        .await;
    assert!(
        result.is_err(),
        "eth_getFilterChanges should fail when filters are disabled"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Method not found") || err.to_string().contains("-32601"),
        "Expected 'Method not found' error, got: {err}"
    );

    let result = seq_test_client
        .get_filter_logs(dummy_filter_id.clone().into())
        .await;
    assert!(
        result.is_err(),
        "eth_getFilterLogs should fail when filters are disabled"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Method not found") || err.to_string().contains("-32601"),
        "Expected 'Method not found' error, got: {err}"
    );

    let result = seq_test_client
        .uninstall_filter(dummy_filter_id.into())
        .await;
    assert!(
        result.is_err(),
        "eth_uninstallFilter should fail when filters are disabled"
    );
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("Method not found") || err.to_string().contains("-32601"),
        "Expected 'Method not found' error, got: {err}"
    );

    Ok(())
}
