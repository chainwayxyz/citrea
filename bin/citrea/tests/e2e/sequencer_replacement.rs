/// In case of a sequencer crash, the runner of the sequencer can replace it one of the full nodes they also run.
/// This feature is useful for high availability.
/// However, there is certain problems that come with it and this feature is subject to be removed in the future.
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::{Signed, TxEip1559, TxEnvelope};
use alloy_rlp::Decodable;
use citrea_sequencer::SequencerMempoolConfig;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag};
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps};
use sov_mock_da::{MockAddress, MockDaService};
use tokio::time::sleep;

use crate::e2e::{copy_dir_recursive, execute_blocks, TestConfig};
use crate::evm::{init_test_rollup, make_test_client};
use crate::test_helpers::{
    create_default_sequencer_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, NodeMode,
};
use crate::{
    DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT, DEFAULT_PROOF_WAIT_DURATION,
    TEST_DATA_GENESIS_PATH,
};

/// Run the sequencer and the full node.
/// After publishing some blocks, the sequencer crashes.
/// The full node is then closed down and reopened as a sequencer.
/// Check if the full node can continue block production.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_crash_and_replace_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    let da_service = MockDaService::with_finality(MockAddress::from([0; 32]), 0, &da_db_dir);
    da_service.publish_test_block().await.unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();

    let da_db_dir_cloned = da_db_dir.clone();
    let sequencer_db_dir_cloned = sequencer_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir_cloned,
            da_db_dir_cloned,
            4,
            true,
            None,
            Some(config1),
            Some(true),
            10,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();
    let config1 = sequencer_config.clone();

    let da_db_dir_cloned = da_db_dir.clone();
    let fullnode_db_dir_cloned = fullnode_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir_cloned,
            da_db_dir_cloned,
            4,
            true,
            None,
            Some(config1),
            Some(true),
            10,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();

    let full_node_test_client = init_test_rollup(full_node_port).await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 4, None).await;

    // second da block
    wait_for_l1_block(&da_service, 2, None).await;

    // Push a new L2 block into the new L1 block(2) to prevent
    // sequencer from falling behind and creating automatic empty block.
    // This makes the process a bit more deterministic on the test's end.
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 5, None).await;
    // Allow for the L2 block to be commited and stored
    // Otherwise, the L2 block height might be registered but it hasn't
    // been processed inside the EVM yet.
    sleep(Duration::from_secs(1)).await;
    assert_eq!(full_node_test_client.eth_block_number().await, 5);

    // assume sequencer craashed
    seq_task.abort();

    wait_for_postgres_commitment(&db_test_client, 1, Some(Duration::from_secs(60))).await;
    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 1);

    full_node_task.abort();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(&fullnode_db_dir, &storage_dir.path().join("full_node_copy"));
    let sequencer_db_dir = storage_dir.path().join("full_node_copy");

    let config1 = sequencer_config.clone();

    // Start the full node as sequencer
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir,
            4,
            true,
            None,
            Some(config1),
            Some(true),
            10,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = make_test_client(seq_port).await;

    assert_eq!(seq_test_client.eth_block_number().await as u64, 5);

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 8, None).await;

    wait_for_l1_block(&da_service, 3, None).await;

    wait_for_postgres_commitment(
        &db_test_client,
        2,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 2);
    assert_eq!(commitments[0].l2_start_height, 1);
    assert_eq!(commitments[0].l2_end_height, 4);
    assert_eq!(commitments[1].l2_start_height, 5);
    assert_eq!(commitments[1].l2_end_height, 8);

    seq_task.abort();

    Ok(())
}

/// Run the sequencer and the full node.
/// After publishing some blocks, the sequencer crashes.
/// The sequencer is reopened.
/// Check if the mempool is restored by checking the txs in the mempool.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_crash_restore_mempool() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    //
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);
    sequencer_config.mempool_conf = SequencerMempoolConfig {
        max_account_slots: 100,
        ..Default::default()
    };

    let da_service =
        MockDaService::with_finality(MockAddress::from([0; 32]), 2, &da_db_dir.clone());
    da_service.publish_test_block().await.unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let da_db_dir_cloned = da_db_dir.clone();
    let sequencer_db_dir_cloned = sequencer_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir_cloned,
            da_db_dir_cloned,
            4,
            true,
            None,
            Some(config1),
            Some(true),
            10,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;

    let send_eth1 = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap();
    let tx_hash = send_eth1.tx_hash();

    let send_eth2 = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap();
    let tx_hash2 = send_eth2.tx_hash();

    let tx_1 = seq_test_client
        .eth_get_transaction_by_hash(*tx_hash, Some(true))
        .await
        .unwrap();
    let tx_2 = seq_test_client
        .eth_get_transaction_by_hash(*tx_hash2, Some(true))
        .await
        .unwrap();

    assert_eq!(tx_1.hash, *tx_hash);
    assert_eq!(tx_2.hash, *tx_hash2);

    // crash and reopen and check if the txs are in the mempool
    seq_task.abort();

    // Copy data into a separate directory since the original sequencer
    // directory is locked by a LOCK file.
    // This would enable us to access ledger DB directly.
    let _ = copy_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_unlocked"),
    );
    let sequencer_db_dir = storage_dir.path().join("sequencer_unlocked").to_path_buf();
    let ledger_db = LedgerDB::with_path(sequencer_db_dir.clone())
        .expect("Should be able to open after stopping the sequencer");
    let txs = ledger_db.get_mempool_txs().unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[1].0, tx_hash.to_vec());
    assert_eq!(txs[0].0, tx_hash2.to_vec());

    let signed_tx = Signed::<TxEip1559>::try_from(tx_1.clone()).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let decoded = TxEnvelope::decode(&mut txs[1].1.as_ref()).unwrap();
    assert_eq!(envelope, decoded);

    // Remove lock
    drop(ledger_db);

    let _ = copy_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_copy"),
    );

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let da_db_dir_cloned = da_db_dir.clone();
    let sequencer_db_dir = storage_dir.path().join("sequencer_copy").to_path_buf();
    let sequencer_db_dir_cloned = sequencer_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir_cloned,
            da_db_dir_cloned,
            4,
            true,
            None,
            Some(config1),
            Some(true),
            10,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;

    // wait for mempool to sync
    sleep(Duration::from_secs(2)).await;

    let tx_1_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx_hash, Some(true))
        .await
        .unwrap();
    let tx_2_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx_hash2, Some(true))
        .await
        .unwrap();

    assert_eq!(tx_1_mempool, tx_1);
    assert_eq!(tx_2_mempool, tx_2);

    // publish block and check if the txs are deleted from pg
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 1, None).await;

    // Mempool removal is an async operation that happens in a different
    // tokio task, wait for 2 seconds for this to execute.
    sleep(Duration::from_secs(2)).await;

    // should be removed from mempool
    assert!(seq_test_client
        .eth_get_transaction_by_hash(*tx_hash, Some(true))
        .await
        .is_none());
    assert!(seq_test_client
        .eth_get_transaction_by_hash(*tx_hash2, Some(true))
        .await
        .is_none());

    seq_task.abort();

    // Copy data into a separate directory since the original sequencer
    // directory is locked by a LOCK file.
    // This would enable us to access ledger DB directly.
    let _ = copy_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_unlocked"),
    );
    let sequencer_db_dir = storage_dir.path().join("sequencer_unlocked").to_path_buf();
    let ledger_db = LedgerDB::with_path(sequencer_db_dir.clone())
        .expect("Should be able to open after stopping the sequencer");
    let txs = ledger_db.get_mempool_txs().unwrap();
    // should be removed from db
    assert_eq!(txs.len(), 0);

    Ok(())
}

/// Run the sequencer and the full node.
/// Check if the full node saves and serves the soft batches by
/// starting a new full node that syncs from the first full node.
#[tokio::test(flavor = "multi_thread")]
async fn test_soft_batch_save() -> Result<(), anyhow::Error> {
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

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
            da_db_dir_cloned,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    let (full_node_port_tx_2, full_node_port_rx_2) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task_2 = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx_2,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(full_node_port),
            fullnode2_db_dir,
            da_db_dir_cloned,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            false,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let full_node_port_2 = full_node_port_rx_2.await.unwrap();
    let full_node_test_client_2 = make_test_client(full_node_port_2).await;

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

    seq_task.abort();
    full_node_task.abort();
    full_node_task_2.abort();

    Ok(())
}
