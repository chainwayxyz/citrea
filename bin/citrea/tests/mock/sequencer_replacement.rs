/// In case of a sequencer crash, the runner of the sequencer can replace it one of the full nodes they also run.
/// This feature is useful for high availability.
/// However, there is certain problems that come with it and this feature is subject to be removed in the future.
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::{Signed, TxEip1559, TxEnvelope};
use alloy::network::TransactionResponse;
use alloy_primitives::Address;
use alloy_rlp::Decodable;
use alloy_rpc_types::BlockNumberOrTag;
use citrea_common::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use sov_db::ledger_db::migrations::copy_db_dir_recursive;
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::SEQUENCER_LEDGER_TABLES;
use sov_mock_da::{MockAddress, MockDaService};
use tokio::time::sleep;

use super::evm::init_test_rollup;
use super::{execute_blocks, TestConfig};
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

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

    let sequencer_config = SequencerConfig {
        mempool_conf: SequencerMempoolConfig {
            max_account_slots: 100,
            ..Default::default()
        },
        ..Default::default()
    };

    let da_service =
        MockDaService::with_finality(MockAddress::from([0; 32]), 2, &da_db_dir.clone());
    da_service.publish_test_block().await.unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
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
        Some(config1),
        None,
        false,
    )
    .await;

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

    assert_eq!(tx_1.tx_hash(), *tx_hash);
    assert_eq!(tx_2.tx_hash(), *tx_hash2);

    // crash and reopen and check if the txs are in the mempool
    seq_task.graceful_shutdown();

    // Copy data into a separate directory since the original sequencer
    // directory is locked by a LOCK file.
    // This would enable us to access ledger DB directly.
    let _ = copy_db_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_unlocked"),
    );

    let sequencer_tables = SEQUENCER_LEDGER_TABLES
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();
    let sequencer_db_dir = storage_dir.path().join("sequencer_unlocked").to_path_buf();
    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
        sequencer_db_dir.as_path(),
        None,
        Some(sequencer_tables.clone()),
    ))
    .unwrap();
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

    let _ = copy_db_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_copy"),
    );

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let sequencer_db_dir = storage_dir.path().join("sequencer_copy").to_path_buf();

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
        Some(config1),
        None,
        true,
    )
    .await;

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

    // publish block and check if the txs are deleted from ledger
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

    seq_task.graceful_shutdown();

    // Copy data into a separate directory since the original sequencer
    // directory is locked by a LOCK file.
    // This would enable us to access ledger DB directly.
    let _ = copy_db_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_unlocked"),
    );
    let sequencer_db_dir = storage_dir.path().join("sequencer_unlocked").to_path_buf();
    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
        sequencer_db_dir.as_path(),
        None,
        Some(sequencer_tables),
    ))
    .unwrap();
    let txs = ledger_db.get_mempool_txs().unwrap();
    // should be removed from db
    assert_eq!(txs.len(), 0);

    Ok(())
}

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
