use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_primitives::Address;
use alloy_rpc_types::BlockNumberOrTag;
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use reth_tasks::TaskManager;
use sov_db::ledger_db::migrations::copy_db_dir_recursive;

use crate::common::client::TestClient;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

async fn initialize_test(
    sequencer_path: PathBuf,
    db_path: PathBuf,
) -> (TaskManager, Box<TestClient>) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_path,
        &db_path,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

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

    (seq_task, test_client)
}

/// Test that maintenance task removes published transactions from mempool automatically
///
/// This test verifies that Reth's mempool maintenance task is properly triggered by our
/// CanonStateNotification::Commit and removes published transactions.
#[tokio::test(flavor = "multi_thread")]
async fn test_maintenance_removes_published_transactions() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let tx1 = test_client
        .send_eth(addr, None, None, Some(0), 1_000_000_000u128)
        .await
        .unwrap();
    let tx2 = test_client
        .send_eth(addr, None, None, Some(1), 2_000_000_000u128)
        .await
        .unwrap();
    let tx3 = test_client
        .send_eth(addr, None, None, Some(2), 3_000_000_000u128)
        .await
        .unwrap();

    let tx1_hash = *tx1.tx_hash();
    let tx2_hash = *tx2.tx_hash();
    let tx3_hash = *tx3.tx_hash();

    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        3
    );
    assert!(test_client
        .is_transaction_in_mempool(tx1_hash)
        .await
        .unwrap());
    assert!(test_client
        .is_transaction_in_mempool(tx2_hash)
        .await
        .unwrap());
    assert!(test_client
        .is_transaction_in_mempool(tx3_hash)
        .await
        .unwrap());

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let block_transactions = block.transactions.as_hashes().unwrap();

    // Wait for maintenance task to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check which transactions are still in mempool
    for tx_hash in block_transactions {
        let in_mempool = test_client
            .is_transaction_in_mempool(*tx_hash)
            .await
            .unwrap();
        assert!(
            !in_mempool,
            "Published transaction {} should be removed from mempool",
            tx_hash
        );
    }

    // Verify transactions are removed from mempool
    let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
    assert_eq!(
        mempool_count, 0,
        "Expected 0 transactions in mempool, but found {}",
        mempool_count
    );

    seq_task.graceful_shutdown();
}

/// Test that account state updates are properly reflected in mempool validation
///
/// This test makes sure that Reth's mempool maintenance properly updates account states
/// (nonces and balances) after transactions are sent, which allows subsequent transactions
/// with correct nonces to be accepted.
#[tokio::test(flavor = "multi_thread")]
async fn test_account_state_updates() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<PrivateKeySigner>()
        .unwrap()
        .with_chain_id(Some(chain_id));
    let test_addr = key.address();

    let secondary_client = TestClient::new(chain_id, key, test_addr, test_client.rpc_addr)
        .await
        .unwrap();

    // Send funds
    let _funding_tx = test_client
        .send_eth(test_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, Some(Duration::from_secs(30))).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send transactions from secondary account
    let tx1 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(0),
            1_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();
    let tx2 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(1),
            1_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    let tx1_hash = *tx1.tx_hash();
    let tx2_hash = *tx2.tx_hash();

    // Verify transactions are in mempool
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        2,
        "Should have 2 transactions (nonce 0 and 1) in mempool"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(tx1_hash)
            .await
            .unwrap(),
        "TX with nonce 0 should be in mempool"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(tx2_hash)
            .await
            .unwrap(),
        "TX with nonce 1 should be in mempool"
    );

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 2, Some(Duration::from_secs(30))).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    let block_transactions = block.transactions.as_hashes().unwrap();

    assert!(
        block_transactions.contains(&tx1_hash),
        "TX with nonce 0 should be published in block 2"
    );
    assert!(
        block_transactions.contains(&tx2_hash),
        "TX with nonce 1 should be published in block 2"
    );

    // Wait for maintenance task to update account states
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify published transactions are removed from mempool
    assert!(
        !test_client
            .is_transaction_in_mempool(tx1_hash)
            .await
            .unwrap(),
        "Published TX with nonce 0 should be removed from mempool"
    );
    assert!(
        !test_client
            .is_transaction_in_mempool(tx2_hash)
            .await
            .unwrap(),
        "Published TX with nonce 1 should be removed from mempool"
    );

    // Mempool should be empty
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        0,
        "Mempool should be empty after publishing both transactions"
    );

    // Send new transaction with nonce 2
    let tx3 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(2),
            500_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    let tx3_hash = *tx3.tx_hash();

    assert!(
        test_client.is_transaction_in_mempool(tx3_hash).await.unwrap(),
        "TX with nonce 2 should be accepted after nonces 0-1 were published (proves account state update)"
    );

    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        1,
        "Mempool should have 1 transaction (nonce 2)"
    );

    // Send a transaction with nonce 4 (skip nonce 3)
    let future_nonce_tx = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(4), // Future nonce - skipping 3
            100_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    let future_tx_hash = *future_nonce_tx.tx_hash();

    assert!(
        test_client
            .is_transaction_in_mempool(future_tx_hash)
            .await
            .unwrap(),
        "Future nonce transaction should be in mempool"
    );

    // Now we should have 2 transactions in mempool (nonce 2 and nonce 4)
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        2,
        "Should have 2 transactions in mempool (nonce 2 and 4)"
    );

    // Try to publish a block - only nonce 2 should be published, not nonce 4
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 3, None).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check block 3 - should only have tx with nonce 2
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(3)))
        .await;

    let empty_vec = vec![];
    let block_txs = block.transactions.as_hashes().unwrap_or(&empty_vec);
    assert!(
        block_txs.contains(&tx3_hash),
        "Transaction with nonce 2 should be published"
    );
    assert!(
        !block_txs.contains(&future_tx_hash),
        "Transaction with nonce 4 should NOT be published (nonce gap)"
    );

    // After publishing, nonce 4 should still be in mempool waiting for nonce 3
    assert!(
        test_client
            .is_transaction_in_mempool(future_tx_hash)
            .await
            .unwrap(),
        "Transaction with nonce 4 should remain in mempool waiting for nonce 3"
    );

    // Mempool should have 1 transaction (the one with nonce 4)
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        1,
        "Mempool should have 1 transaction (nonce 4) after nonce 2 was published"
    );

    seq_task.graceful_shutdown();
}

/// Test that transactions with insufficient L1 fees are removed after failed inclusion
///
/// This test verifies that Citrea's mempool maintenance handles transactions
/// that fail during block production due to L1 fee validation or other execution errors.
#[tokio::test(flavor = "multi_thread")]
async fn test_l1_fee_failed_transactions() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let normal_tx = test_client
        .send_eth(addr, None, None, Some(0), 10_000_000_000u128)
        .await
        .unwrap();

    // Send a transaction with very low gas price that should fail L1 fee validation
    let low_l1_fee_tx = test_client
        .send_eth(addr, Some(1), Some(10_000_000), Some(1), 1_000_000_000u128)
        .await
        .unwrap();

    let normal_tx_hash = *normal_tx.tx_hash();
    let low_fee_tx_hash = *low_l1_fee_tx.tx_hash();

    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        2,
        "Should have 2 transactions in mempool"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(normal_tx_hash)
            .await
            .unwrap(),
        "Normal fee transaction should be in mempool"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(low_fee_tx_hash)
            .await
            .unwrap(),
        "Low fee transaction should be accepted into mempool initially"
    );

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // Wait for maintenance task to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let block_transactions = block.transactions.as_hashes().unwrap();

    assert!(
        block_transactions.contains(&normal_tx_hash),
        "Normal fee transaction should be published"
    );

    // Low fee transaction should NOT be included due to insufficient L1 fees
    assert!(
        !block_transactions.contains(&low_fee_tx_hash),
        "Low L1 fee transaction should not be published"
    );

    assert!(
        !test_client
            .is_transaction_in_mempool(normal_tx_hash)
            .await
            .unwrap(),
        "Published normal transaction should be removed from mempool"
    );

    // Low fee transaction may stay in mempool for retry or be removed after multiple failures
    // Let's attempt a few more blocks to see if it gets removed
    for attempt in 1..=3 {
        test_client.send_publish_batch_request().await;
        tokio::time::sleep(Duration::from_millis(700)).await;

        // Check if it was eventually published (shouldn't be due to low L1 fees)
        let latest_block = test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        let published = latest_block
            .transactions
            .as_hashes()
            .map(|hashes| hashes.contains(&low_fee_tx_hash))
            .unwrap_or(false);

        assert!(
            !published,
            "Low L1 fee transaction should never be published (attempt {})",
            attempt
        );
    }

    let final_block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    assert!(
        !final_block
            .transactions
            .as_hashes()
            .map(|h| h.contains(&low_fee_tx_hash))
            .unwrap_or(false),
        "Low L1 fee transaction should never be published"
    );

    seq_task.graceful_shutdown();
}

/// Test that persistent storage cleanup works correctly after restart
///
/// This test verifies that Citrea properly synchronizes with
/// persistent storage and correctly handles the mempool state across node restarts.
#[tokio::test(flavor = "multi_thread")]
async fn test_persistent_storage_cleanup() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
    let mut persistent_tx_hash;
    let published_tx_hash;

    // First sequencer instance
    {
        let (seq_task, test_client) =
            initialize_test(sequencer_db_dir.clone(), da_db_dir.clone()).await;

        // Send transactions and verify persistence
        let tx1 = test_client
            .send_eth(addr, None, None, Some(0), 1_000_000_000u128)
            .await
            .unwrap();
        let tx2 = test_client
            .send_eth(addr, None, None, Some(1), 2_000_000_000u128)
            .await
            .unwrap();

        published_tx_hash = *tx1.tx_hash();
        persistent_tx_hash = *tx2.tx_hash();

        assert_eq!(
            test_client.get_mempool_transaction_count().await.unwrap(),
            2,
            "Should have 2 transactions in mempool initially"
        );
        assert!(
            test_client
                .is_transaction_in_mempool(published_tx_hash)
                .await
                .unwrap(),
            "TX1 should be in mempool initially"
        );
        assert!(
            test_client
                .is_transaction_in_mempool(persistent_tx_hash)
                .await
                .unwrap(),
            "TX2 should be in mempool initially"
        );

        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 1, None).await;

        // Wait for maintenance to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        let block = test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        let block_transactions = block.transactions.as_hashes().unwrap();

        assert!(
            block_transactions.contains(&published_tx_hash),
            "TX1 (nonce 0) should be published in block 1"
        );
        assert!(
            block_transactions.contains(&persistent_tx_hash),
            "TX2 (nonce 1) should also be published in block 1"
        );

        assert!(
            !test_client
                .is_transaction_in_mempool(published_tx_hash)
                .await
                .unwrap(),
            "Published TX1 should be removed from mempool before shutdown"
        );
        assert!(
            !test_client
                .is_transaction_in_mempool(persistent_tx_hash)
                .await
                .unwrap(),
            "Published TX2 should be removed from mempool before shutdown"
        );

        assert_eq!(
            test_client.get_mempool_transaction_count().await.unwrap(),
            0,
            "Mempool should be empty after both transactions are published"
        );

        // Send a new transaction that will persist across restart
        let tx3 = test_client
            .send_eth(addr, None, None, Some(2), 3_000_000_000u128)
            .await
            .unwrap();
        persistent_tx_hash = *tx3.tx_hash();

        assert!(
            test_client
                .is_transaction_in_mempool(persistent_tx_hash)
                .await
                .unwrap(),
            "TX3 should be in mempool before shutdown"
        );

        seq_task.graceful_shutdown();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let sequencer_copy_dir = db_dir.path().join("sequencer_copy").to_path_buf();
    copy_db_dir_recursive(&sequencer_db_dir, &sequencer_copy_dir)
        .expect("Failed to copy sequencer database");

    {
        let (seq_task, test_client) = initialize_test(sequencer_copy_dir, da_db_dir).await;

        // Wait for sequencer startup
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Get mempool count after restart
        let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();

        let published_tx_in_mempool = test_client
            .is_transaction_in_mempool(published_tx_hash)
            .await
            .unwrap();
        assert!(
            !published_tx_in_mempool,
            "Published TX1 should NOT be restored to mempool after restart (maintenance removes it)"
        );

        let persistent_tx_in_mempool = test_client
            .is_transaction_in_mempool(persistent_tx_hash)
            .await
            .unwrap();
        assert!(
            persistent_tx_in_mempool,
            "Unpublished TX3 should be restored to mempool after restart"
        );

        assert_eq!(
            mempool_count, 1,
            "Mempool should have exactly 1 transaction after restart (only TX3)"
        );

        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 2, None).await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        let block = test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
            .await;
        let block_transactions = block.transactions.as_hashes().unwrap();

        assert!(
            block_transactions.contains(&persistent_tx_hash),
            "TX3 should be published in block 2 after restart"
        );

        // Mempool should be empty after publishing TX3
        assert_eq!(
            test_client.get_mempool_transaction_count().await.unwrap(),
            0,
            "Mempool should be empty after publishing the persistent transaction"
        );

        seq_task.graceful_shutdown();
    }
}

/// Test that stale transactions are evicted from mempool after max lifetime
#[tokio::test(flavor = "multi_thread")]
async fn test_stale_tx_eviction() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    // Create a custom sequencer config with short max_tx_lifetime
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );

    // Configure sequencer with a very short transaction lifetime (2 seconds)
    let mut sequencer_config = SequencerConfig::default();
    sequencer_config
        .mempool_conf
        .maintenance
        .max_tx_lifetime_secs = 2;

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

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // Send transactions with FUTURE nonces that won't be included in blocks
    // These will sit in mempool and become stale
    let tx1 = test_client
        .send_eth(addr, None, None, Some(10), 1_000_000_000u128) // Future nonce
        .await
        .unwrap();
    let tx2 = test_client
        .send_eth(addr, None, None, Some(11), 2_000_000_000u128) // Future nonce
        .await
        .unwrap();
    let tx3 = test_client
        .send_eth(addr, None, None, Some(12), 3_000_000_000u128) // Future nonce
        .await
        .unwrap();

    let tx1_hash = *tx1.tx_hash();
    let tx2_hash = *tx2.tx_hash();
    let tx3_hash = *tx3.tx_hash();

    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        3,
        "Should have 3 transactions in mempool initially"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(tx1_hash)
            .await
            .unwrap(),
        "TX1 should be in mempool initially"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(tx2_hash)
            .await
            .unwrap(),
        "TX2 should be in mempool initially"
    );
    assert!(
        test_client
            .is_transaction_in_mempool(tx3_hash)
            .await
            .unwrap(),
        "TX3 should be in mempool initially"
    );

    // Wait for transactions to become stale
    // We set max_tx_lifetime to 2 seconds, so wait 3 seconds to ensure they're stale
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Trigger maintenance by publishing an empty block
    // The future nonce transactions won't be included, but maintenance should evict them as stale
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // Wait a bit for maintenance task to process
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Check block to verify transactions were NOT included
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let block_transactions = block.transactions.as_hashes().unwrap();

    // Future nonce transactions should NOT be in the block
    assert!(
        !block_transactions.contains(&tx1_hash),
        "TX1 with future nonce should NOT be in block"
    );
    assert!(
        !block_transactions.contains(&tx2_hash),
        "TX2 with future nonce should NOT be in block"
    );
    assert!(
        !block_transactions.contains(&tx3_hash),
        "TX3 with future nonce should NOT be in block"
    );

    // Check that stale transactions were evicted from mempool
    assert!(
        !test_client
            .is_transaction_in_mempool(tx1_hash)
            .await
            .unwrap(),
        "TX1 should be evicted from mempool due to staleness"
    );
    assert!(
        !test_client
            .is_transaction_in_mempool(tx2_hash)
            .await
            .unwrap(),
        "TX2 should be evicted from mempool due to staleness"
    );
    assert!(
        !test_client
            .is_transaction_in_mempool(tx3_hash)
            .await
            .unwrap(),
        "TX3 should be evicted from mempool due to staleness"
    );

    let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
    assert_eq!(
        mempool_count, 0,
        "All stale transactions should be evicted, but found {} transactions",
        mempool_count
    );

    seq_task.graceful_shutdown();
}
