use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use alloy::consensus::{Signed, TxEip1559, TxEnvelope};
use alloy::signers::wallet::LocalWallet;
use alloy::signers::Signer;
use alloy_rlp::{BytesMut, Decodable, Encodable};
use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_evm::SYSTEM_SIGNER;
use citrea_primitives::TEST_PRIVATE_KEY;
use citrea_sequencer::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use ethereum_rpc::CitreaStatus;
use reth_primitives::{Address, BlockNumberOrTag, TxHash, U256};
use shared_backup_db::{PostgresConnector, ProofType, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec, MockHash};
use sov_rollup_interface::da::{DaData, DaSpec};
use sov_rollup_interface::rpc::{ProofRpcResponse, SoftConfirmationStatus};
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_sequencer_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, wait_for_postgres_commitment, wait_for_postgres_proofs, wait_for_proof,
    wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

struct TestConfig {
    seq_min_soft_confirmations: u64,
    deposit_mempool_fetch_limit: usize,
    sequencer_path: PathBuf,
    fullnode_path: PathBuf,
    da_path: PathBuf,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            seq_min_soft_confirmations: DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            deposit_mempool_fetch_limit: 10,
            sequencer_path: PathBuf::new(),
            fullnode_path: PathBuf::new(),
            da_path: PathBuf::new(),
        }
    }
}

async fn initialize_test(
    config: TestConfig,
) -> (
    Box<TestClient>, /* seq_test_client */
    Box<TestClient>, /* full_node_test_client */
    JoinHandle<()>,  /* seq_task */
    JoinHandle<()>,  /* full_node_task */
    Address,
) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let db_path = config.da_path.clone();
    let sequencer_path = config.sequencer_path.clone();
    let fullnode_path = config.fullnode_path.clone();

    let db_path1 = db_path.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_path,
            db_path1,
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
    let seq_test_client = make_test_client(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let db_path2 = db_path.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_path,
            db_path2,
            config.seq_min_soft_confirmations,
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

    (
        seq_test_client,
        full_node_test_client,
        seq_task,
        full_node_task,
        Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_batch_save() -> Result<(), anyhow::Error> {
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

#[tokio::test(flavor = "multi_thread")]
async fn test_full_node_send_tx() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, addr) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            ..Default::default()
        })
        .await;

    let tx_hash = full_node_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;

    wait_for_l2_block(&seq_test_client, 1, None).await;
    wait_for_l2_block(&full_node_test_client, 1, None).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let sq_transactions = sq_block.transactions.as_hashes().unwrap();
    let full_node_transactions = full_node_block.transactions.as_hashes().unwrap();
    assert!(sq_transactions.contains(tx_hash.tx_hash()));
    assert!(full_node_transactions.contains(tx_hash.tx_hash()));
    assert_eq!(
        sq_block.header.state_root,
        full_node_block.header.state_root
    );

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delayed_sync_ten_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
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

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..10 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 10, None).await;

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
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    wait_for_l2_block(&full_node_test_client, 10, None).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;

    assert_eq!(
        seq_block.header.state_root,
        full_node_block.header.state_root
    );
    assert_eq!(seq_block.header.hash, full_node_block.header.hash);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_e2e_same_block_sync() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            sequencer_path: sequencer_db_dir,
            da_path: da_db_dir.clone(),
            fullnode_path: fullnode_db_dir,
            ..Default::default()
        })
        .await;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client, &da_db_dir).await;

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_close_and_reopen_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
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

    let seq_port = seq_port_rx.await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let fullnode_db_dir_cloned = fullnode_db_dir.clone();
    // starting full node with db path
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
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

    let seq_test_client = init_test_rollup(seq_port).await;
    let full_node_test_client = init_test_rollup(full_node_port).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // create 10 blocks
    for _ in 0..10 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    // wait for full node to sync
    wait_for_l2_block(&full_node_test_client, 10, None).await;

    // check if latest blocks are the same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.header.number.unwrap(), 10);
    assert_eq!(full_node_last_block.header.number.unwrap(), 10);

    assert_eq!(
        seq_last_block.header.state_root,
        full_node_last_block.header.state_root
    );
    assert_eq!(seq_last_block.header.hash, full_node_last_block.header.hash);

    // close full node
    rollup_task.abort();

    // create 100 more blocks
    for _ in 0..100 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);
    da_service.publish_test_block().await.unwrap();

    // start full node again
    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(&fullnode_db_dir, &storage_dir.path().join("fullnode_copy"));

    let da_db_dir_cloned = da_db_dir.clone();
    let fullnode_db_dir = storage_dir.path().join("fullnode_copy");
    // spin up the full node again with the same data where it left of only with different path to not stuck on lock
    let rollup_task = tokio::spawn(async move {
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
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();

    let full_node_test_client = make_test_client(full_node_port).await;

    wait_for_l2_block(&seq_test_client, 110, None).await;
    wait_for_l2_block(&full_node_test_client, 110, None).await;

    // check if the latest block state roots are same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.header.number.unwrap(), 110);
    assert_eq!(full_node_last_block.header.number.unwrap(), 110);

    assert_eq!(
        seq_last_block.header.state_root,
        full_node_last_block.header.state_root
    );
    assert_eq!(seq_last_block.header.hash, full_node_last_block.header.hash);

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_transaction_by_hash() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_dir_cloned,
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

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_dir_cloned = da_db_dir.clone();
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
            da_dir_cloned,
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

    let seq_test_client = init_test_rollup(seq_port).await;
    let full_node_test_client = init_test_rollup(full_node_port).await;

    // create some txs to test the use cases
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    let pending_tx1 = seq_test_client
        .send_eth(addr, None, None, None, 1_000_000_000u128)
        .await
        .unwrap();

    let pending_tx2 = seq_test_client
        .send_eth(addr, None, None, None, 1_000_000_000u128)
        .await
        .unwrap();
    // currently there are two txs in the pool, the full node should be able to get them
    // should get with mempool_only true
    let tx1 = full_node_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
        .await
        .unwrap();
    // Should get with mempool_only false/none
    let tx2 = full_node_test_client
        .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_none());
    assert!(tx2.block_hash.is_none());
    assert_eq!(tx1.hash, *pending_tx1.tx_hash());
    assert_eq!(tx2.hash, *pending_tx2.tx_hash());

    // sequencer should also be able to get them
    // Should get just by checking the pool
    let tx1 = seq_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
        .await
        .unwrap();
    let tx2 = seq_test_client
        .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_none());
    assert!(tx2.block_hash.is_none());
    assert_eq!(tx1.hash, *pending_tx1.tx_hash());
    assert_eq!(tx2.hash, *pending_tx2.tx_hash());

    seq_test_client.send_publish_batch_request().await;

    // wait for the full node to sync
    wait_for_l2_block(&full_node_test_client, 1, None).await;

    // make sure txs are in the block
    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let seq_block_transactions = seq_block.transactions.as_hashes().unwrap();
    assert!(seq_block_transactions.contains(pending_tx1.tx_hash()));
    assert!(seq_block_transactions.contains(pending_tx2.tx_hash()));

    // same operations after the block is published, both sequencer and full node should be able to get them.
    // should not get with mempool_only true because it checks the sequencer mempool only
    let non_existent_tx = full_node_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
        .await;
    // this should be none because it is not in the mempool anymore
    assert!(non_existent_tx.is_none());

    let tx1 = full_node_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
        .await
        .unwrap();
    let tx2 = full_node_test_client
        .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_some());
    assert!(tx2.block_hash.is_some());
    assert_eq!(tx1.hash, *pending_tx1.tx_hash());
    assert_eq!(tx2.hash, *pending_tx2.tx_hash());

    // should not get with mempool_only true because it checks mempool only
    let none_existent_tx = seq_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
        .await;
    // this should be none because it is not in the mempool anymore
    assert!(none_existent_tx.is_none());

    // In other cases should check the block and find the tx
    let tx1 = seq_test_client
        .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
        .await
        .unwrap();
    let tx2 = seq_test_client
        .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_some());
    assert!(tx2.block_hash.is_some());
    assert_eq!(tx1.hash, *pending_tx1.tx_hash());
    assert_eq!(tx2.hash, *pending_tx2.tx_hash());

    // create random tx hash and make sure it returns None
    let random_tx_hash: TxHash = TxHash::random();
    assert!(seq_test_client
        .eth_get_transaction_by_hash(random_tx_hash, None)
        .await
        .is_none());
    assert!(full_node_test_client
        .eth_get_transaction_by_hash(random_tx_hash, None)
        .await
        .is_none());

    seq_task.abort();
    rollup_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_on_different_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            ..Default::default()
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 6, None).await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    let mut last_da_slot_height = 0;
    let mut last_da_slot_hash = <MockDaSpec as DaSpec>::SlotHash::from([0u8; 32]);

    // now retrieve soft confirmations from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let seq_soft_conf = seq_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();

        if i != 1 {
            assert_eq!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_eq!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        }

        assert_eq!(
            seq_soft_conf.da_slot_height,
            full_node_soft_conf.da_slot_height
        );

        assert_eq!(seq_soft_conf.da_slot_hash, full_node_soft_conf.da_slot_hash);

        last_da_slot_height = seq_soft_conf.da_slot_height;
        last_da_slot_hash = MockHash(seq_soft_conf.da_slot_hash);
    }

    // publish new da block
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    for _ in 1..=6 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }

    wait_for_l2_block(&seq_test_client, 12, None).await;
    wait_for_l2_block(&full_node_test_client, 12, None).await;

    for i in 7..=12 {
        let seq_soft_conf = seq_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();

        if i != 7 {
            assert_eq!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_eq!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        } else {
            assert_ne!(last_da_slot_height, seq_soft_conf.da_slot_height);
            assert_ne!(last_da_slot_hash, MockHash(seq_soft_conf.da_slot_hash));
        }

        assert_eq!(
            seq_soft_conf.da_slot_height,
            full_node_soft_conf.da_slot_height
        );

        assert_eq!(seq_soft_conf.da_slot_hash, full_node_soft_conf.da_slot_hash);

        last_da_slot_height = seq_soft_conf.da_slot_height;
        last_da_slot_hash = MockHash(seq_soft_conf.da_slot_hash);
    }

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_reopen_sequencer() -> Result<(), anyhow::Error> {
    // open, close without publishing blokcs
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let sequencer_db_dir_cloned = sequencer_db_dir.clone();
    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir_cloned,
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

    let seq_test_client = init_test_rollup(seq_port).await;

    let block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    assert_eq!(block.header.number.unwrap(), 0);

    // close sequencer
    seq_task.abort();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_copy"),
    );

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);
    da_service.publish_test_block().await.unwrap();

    wait_for_l1_block(&da_service, 1, None).await;

    let sequencer_db_dir = storage_dir.path().join("sequencer_copy");
    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
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

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = make_test_client(seq_port).await;

    let seq_last_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    // make sure the state roots are the same
    assert_eq!(seq_last_block.header.state_root, block.header.state_root);
    assert_eq!(
        seq_last_block.header.number.unwrap(),
        block.header.number.unwrap()
    );

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    wait_for_l2_block(&seq_test_client, 2, None).await;

    assert_eq!(
        seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await
            .header
            .number
            .unwrap(),
        2
    );

    seq_task.abort();

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let target_path = dst.join(entry.file_name());

        if entry_path.is_dir() {
            copy_dir_recursive(&entry_path, &target_path)?;
        } else {
            fs::copy(&entry_path, &target_path)?;
        }
    }
    Ok(())
}

async fn execute_blocks(
    sequencer_client: &TestClient,
    full_node_client: &TestClient,
    da_db_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code(), None)
            .await?;
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(42), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.watch().await.unwrap();
    }

    sequencer_client.send_publish_batch_request().await;

    {
        for temp in 0..10 {
            let _set_value_req = sequencer_client
                .contract_transaction(contract_address, contract.set_call_data(78 + temp), None)
                .await;
        }
        sequencer_client.send_publish_batch_request().await;
    }

    {
        for _ in 0..200 {
            sequencer_client.send_publish_batch_request().await;
        }

        wait_for_l2_block(sequencer_client, 204, None).await;
    }

    let da_service = MockDaService::new(MockAddress::from([0; 32]), da_db_dir);
    da_service.publish_test_block().await.unwrap();

    {
        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..300 {
            let _pending = sequencer_client
                .send_eth(addr, None, None, None, 0u128)
                .await
                .unwrap();
            sequencer_client.send_publish_batch_request().await;
        }
    }

    wait_for_l2_block(sequencer_client, 504, None).await;
    wait_for_l2_block(full_node_client, 504, None).await;

    let seq_last_block = sequencer_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.header.number.unwrap(), 504);
    assert_eq!(full_node_last_block.header.number.unwrap(), 504);

    assert_eq!(
        seq_last_block.header.state_root,
        full_node_last_block.header.state_root
    );
    assert_eq!(seq_last_block.header.hash, full_node_last_block.header.hash);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_status_one_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir);

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Trusted, status_node.unwrap());
    }

    // publish new da block
    //
    // This will trigger the sequencer's DA monitor to see a newly published
    // block and will therefore initiate a commitment submission to the MockDA.
    // Therefore, creating yet another DA block.
    da_service.publish_test_block().await.unwrap();

    // The above L1 block has been created,
    // we wait until the block is actually received by the DA monitor.
    wait_for_l1_block(&da_service, 2, None).await;

    // Wait for DA block #3 containing the commitment
    // submitted by sequencer.
    wait_for_l1_block(&da_service, 3, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Finalized, status_node.unwrap());
    }

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_soft_confirmations_status_two_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=2 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 2, None).await;

    // publish new da block
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    for _ in 2..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&full_node_test_client, 7, None).await;

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=2 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Trusted, status_node.unwrap());
    }

    // publish new da block
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 3, None).await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    wait_for_l2_block(&full_node_test_client, 9, None).await;

    // Check that these L2 blocks are bounded on different L1 block
    let mut batch_infos = vec![];
    for i in 1..=6 {
        let full_node_soft_conf = full_node_test_client
            .ledger_get_soft_batch_by_number::<MockDaSpec>(i)
            .await
            .unwrap();
        batch_infos.push(full_node_soft_conf);
    }
    assert_eq!(batch_infos[0].da_slot_height, batch_infos[1].da_slot_height);
    assert!(batch_infos[2..]
        .iter()
        .all(|x| x.da_slot_height == batch_infos[2].da_slot_height));
    assert_ne!(batch_infos[0].da_slot_height, batch_infos[5].da_slot_height);

    // now retrieve confirmation status from the sequencer and full node and check if they are the same
    for i in 1..=6 {
        let status_node = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap();

        assert_eq!(SoftConfirmationStatus::Finalized, status_node.unwrap());
    }

    let status_node = full_node_test_client
        .ledger_get_soft_confirmation_status(410)
        .await;

    assert!(format!("{:?}", status_node.err())
        .contains("Soft confirmation at height 410 not processed yet."));

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_prover_sync_with_commitments() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir);

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
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                db_config: Some(SharedBackupDbConfig::default()),
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
    let prover_node_test_client = make_test_client(prover_node_port).await;

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);

    // start l1 height = 1, end = 2
    seq_test_client.send_publish_batch_request().await;

    // sequencer commitment should be sent
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;
    wait_for_l1_block(&da_service, 3, None).await;

    seq_test_client.send_publish_batch_request().await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        3,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    // prover should have synced all 4 l2 blocks
    wait_for_l2_block(&prover_node_test_client, 4, None).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    seq_test_client.send_publish_batch_request().await;

    // Still should have 4 blocks there are no commitments yet
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    // Still should have 4 blocks there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 4, None).await;
    wait_for_l1_block(&da_service, 5, None).await;

    seq_test_client.send_publish_batch_request().await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        5,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    // Should now have 8 blocks = 2 commitments of blocks 1-4 and 5-9
    // there is an extra soft confirmation due to the prover publishing a proof. This causes
    // a new MockDa block, which in turn causes the sequencer to publish an extra soft confirmation
    // becase it must not skip blocks.
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    // on the 8th DA block, we should have a proof
    let mut blobs = da_service.get_block_at(4).await.unwrap().blobs;

    assert_eq!(blobs.len(), 1);

    let mut blob = blobs.pop().unwrap();
    blob.data.advance(blob.data.total_len());

    let da_data = blob.data.accumulator();

    let proof: DaData = borsh::BorshDeserialize::try_from_slice(da_data).unwrap();

    assert!(matches!(proof, DaData::ZKProof(_)));

    // TODO: Also test with multiple commitments in single Mock DA Block
    seq_task.abort();
    prover_node_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_reopen_prover() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig::default()),
            NodeMode::SequencerNode,
            sequencer_db_dir,
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

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_db_dir_cloned = prover_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig::default()),
            NodeMode::Prover(seq_port),
            prover_db_dir_cloned,
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
    let prover_node_test_client = make_test_client(prover_node_port).await;

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&seq_test_client, 3, None).await;

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 4, None).await;

    // sequencer commitment should be sent
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 3, None).await;
    // Block that contains the commitment
    wait_for_l1_block(&da_service, 4, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        5,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;
    // Contains the proof
    wait_for_l1_block(&da_service, 5, None).await;

    // prover should have synced all 4 l2 blocks
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    prover_node_task.abort();

    let _ = copy_dir_recursive(&prover_db_dir, &storage_dir.path().join("prover_copy"));

    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let prover_copy_db_dir = storage_dir.path().join("prover_copy");
    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig::default()),
            NodeMode::Prover(seq_port),
            prover_copy_db_dir,
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
    let prover_node_test_client = make_test_client(prover_node_port).await;

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 6, None).await;

    // Still should have 4 blocks there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    prover_node_task.abort();

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 8, None).await;

    let _ = copy_dir_recursive(&prover_db_dir, &storage_dir.path().join("prover_copy2"));

    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let prover_copy2_dir_cloned = storage_dir.path().join("prover_copy2");
    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig::default()),
            NodeMode::Prover(seq_port),
            prover_copy2_dir_cloned,
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
    let prover_node_test_client = make_test_client(prover_node_port).await;

    // Publish a DA to force prover to process new blocks
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 6, None).await;

    // We have 8 blocks in total, make sure the prover syncs
    // and starts proving the second commitment.
    wait_for_l2_block(&prover_node_test_client, 8, Some(Duration::from_secs(300))).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 8);

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 9, None).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 7, None).await;
    // Commitment is sent
    wait_for_l1_block(&da_service, 8, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        9,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    // Should now have 8 blocks = 2 commitments of blocks 1-4 and 5-8
    // there is an extra soft confirmation due to the prover publishing a proof. This causes
    // a new MockDa block, which in turn causes the sequencer to publish an extra soft confirmation
    // TODO: Debug why this is not including block 9 in the commitment
    // https://github.com/chainwayxyz/citrea/issues/684
    assert!(prover_node_test_client.eth_block_number().await >= 8);
    // TODO: Also test with multiple commitments in single Mock DA Block
    seq_task.abort();
    prover_node_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_system_transactions() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let system_contract_address =
        Address::from_str("0x3100000000000000000000000000000000000001").unwrap();
    let system_signer_address = Address::from_slice(SYSTEM_SIGNER.as_slice());

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir,
            sequencer_path: sequencer_db_dir,
            fullnode_path: fullnode_db_dir,
            ..Default::default()
        })
        .await;

    // publish some blocks with system transactions
    for i in 0..10 {
        for _ in 0..5 {
            seq_test_client.spam_publish_batch_request().await.unwrap();
        }
        wait_for_l2_block(&seq_test_client, 5 * (i + 1), None).await;

        da_service.publish_test_block().await.unwrap();

        wait_for_l1_block(&da_service, 4 + i, None).await;
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 51, None).await;

    // check block 1-6-11-16-21-26-31-36-41-46-51 has system transactions
    for i in 0..=10 {
        let block_num = 1 + i * 5;

        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(block_num)))
            .await;

        if block_num == 1 {
            let block_transactions = block.transactions.as_transactions().unwrap();
            assert_eq!(block_transactions.len(), 3);

            let init_tx = &block_transactions[0];
            let set_tx = &block_transactions[1];

            assert_eq!(init_tx.from, system_signer_address);
            assert_eq!(init_tx.to.unwrap(), system_contract_address);
            assert_eq!(
                init_tx.input[..],
                *hex::decode(
                    "1f5783330000000000000000000000000000000000000000000000000000000000000003"
                )
                .unwrap()
                .as_slice()
            );

            assert_eq!(set_tx.from, system_signer_address);
            assert_eq!(set_tx.to.unwrap(), system_contract_address);
            assert_eq!(
                set_tx.input[0..4],
                *hex::decode("0e27bc11").unwrap().as_slice()
            );
        } else {
            let block_transactions = block.transactions.as_transactions().unwrap();
            assert_eq!(block_transactions.len(), 1);

            let tx = &block_transactions[0];

            assert_eq!(tx.from, system_signer_address);
            assert_eq!(tx.to.unwrap(), system_contract_address);
            assert_eq!(tx.input[0..4], *hex::decode("0e27bc11").unwrap().as_slice());
        }
    }

    // and other blocks don't have
    for i in 0..=51 {
        if i % 5 == 1 {
            continue;
        }

        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(i)))
            .await;

        assert_eq!(block.transactions.len(), 0);
    }

    // now check hashes
    for i in 3..=13 {
        let da_block = da_service.get_block_at(i).await.unwrap();

        let hash_on_chain: String = full_node_test_client
            .contract_call(
                system_contract_address,
                BitcoinLightClient::get_block_hash(i).to_vec(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            &da_block.header.hash.0,
            hex::decode(hash_on_chain.clone().split_off(2))
                .unwrap()
                .as_slice()
        );

        // check block response as well
        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number((i - 3) * 5 + 1)))
            .await;

        assert_eq!(block.other.get("l1Hash"), Some(&hash_on_chain.into()));
    }

    let seq_last_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let node_last_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block, node_last_block);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_system_tx_effect_on_block_gas_limit() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(
                "../../resources/test-data/integration-tests-low-block-gas-limit",
            ),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            // Increase max account slots to not stuck as spammer
            Some(SequencerConfig {
                private_key: TEST_PRIVATE_KEY.to_string(),
                min_soft_confirmations_per_commitment: 1000,
                test_mode: true,
                deposit_mempool_fetch_limit: 10,
                mempool_conf: SequencerMempoolConfig {
                    max_account_slots: 100,
                    ..Default::default()
                },
                db_config: Default::default(),
                da_update_interval_ms: 1000,
                block_production_interval_ms: 500,
            }),
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;
    // sys tx use L1BlockHash(48522 + 78491) + Bridge(258971) = 385984 gas
    // the block gas limit is 1_500_000 because the system txs gas limit is 1_500_000 (decided with @eyusufatik and @okkothejawa as bridge init takes 1M gas)

    // 1500000 - 385984 = 1114016 gas left in block
    // 1114016 / 21000 = 53,04... so 53 ether transfer transactions can be included in the block

    // send 53 ether transfer transactions
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..52 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
    }

    // 53th tx should be the last tx in the soft batch
    let last_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    // 54th tx should not be in soft batch
    let not_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let last_in_receipt = last_in_tx.unwrap().get_receipt().await.unwrap();

    wait_for_l2_block(&seq_test_client, 1, None).await;

    let initial_soft_batch = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(1)
        .await
        .unwrap();

    let last_tx_hash = last_in_receipt.transaction_hash;
    let last_tx = seq_test_client
        .eth_get_transaction_by_hash(last_tx_hash, Some(false))
        .await
        .unwrap();
    let signed_tx = Signed::<TxEip1559>::try_from(last_tx).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let mut last_tx_raw = BytesMut::new();
    envelope.encode(&mut last_tx_raw);

    assert!(last_in_receipt.block_number.is_some());

    // last in tx byte array should be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_batch.clone().txs.unwrap()[0].tx.as_slice(),
        &last_tx_raw[2..]
    )
    .is_some());

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let not_in_receipt = not_in_tx.unwrap().get_receipt().await.unwrap();

    let not_in_hash = not_in_receipt.transaction_hash;

    let not_in_tx = seq_test_client
        .eth_get_transaction_by_hash(not_in_hash, Some(false))
        .await
        .unwrap();
    let signed_tx = Signed::<TxEip1559>::try_from(not_in_tx).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let mut not_in_raw = BytesMut::new();
    envelope.encode(&mut not_in_raw);

    // not in tx byte array should not be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_batch.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw[2..]
    )
    .is_none());

    seq_test_client.send_publish_batch_request().await;

    let second_soft_batch = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(2)
        .await
        .unwrap();

    // should be in tx byte array of the soft batch after
    assert!(find_subarray(
        second_soft_batch.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw[2..]
    )
    .is_some());

    let block1 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // the last in tx should be in the block
    let block1_transactions = block1.transactions.as_hashes().unwrap();
    assert!(block1_transactions.iter().any(|tx| tx == &last_tx_hash));
    // and the other tx should not be in
    assert!(!block1_transactions.iter().any(|tx| tx == &not_in_hash));

    let block2 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    // the other tx should be in second block
    let block2_transactions = block2.transactions.as_hashes().unwrap();
    assert!(block2_transactions.iter().any(|tx| tx == &not_in_hash));

    seq_task.abort();

    Ok(())
}

fn find_subarray(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn sequencer_crash_and_replace_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let psql_db_name = "sequencer_crash_and_replace_full_node".to_owned();

    let db_test_client = PostgresConnector::new_test_client(psql_db_name.clone())
        .await
        .unwrap();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    sequencer_config.db_config = Some(SharedBackupDbConfig::default().set_db_name(psql_db_name));

    let da_service = MockDaService::with_finality(MockAddress::from([0; 32]), 2, &da_db_dir);
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
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;
    wait_for_l1_block(&da_service, 3, None).await;

    // before this the commitment will be sent
    // the commitment will be only in the first block so it is still not finalized
    // so the full node won't see the commitment
    seq_test_client.send_publish_batch_request().await;

    // wait for sync
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // should be synced
    assert_eq!(full_node_test_client.eth_block_number().await, 6);

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

    wait_for_l2_block(&seq_test_client, 6, None).await;

    assert_eq!(seq_test_client.eth_block_number().await as u64, 6);

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 9, None).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 4, None).await;
    wait_for_l1_block(&da_service, 5, None).await;

    // new commitment will be sent here, it should send between 2 and 3 should not include 1
    seq_test_client.send_publish_batch_request().await;

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
    // TODO: This is a bug that should be checked.
    // The second commitment L2 start height should be 5
    assert_eq!(commitments[1].l2_start_height, 1);
    assert_eq!(commitments[1].l2_end_height, 9);

    seq_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_failing_on_l1_is_removed_from_mempool() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            da_path: da_db_dir.clone(),
            sequencer_path: sequencer_db_dir.clone(),
            fullnode_path: fullnode_db_dir.clone(),
            ..Default::default()
        })
        .await;

    let random_wallet = LocalWallet::random().with_chain_id(Some(seq_test_client.chain_id));

    let random_wallet_address = random_wallet.address();

    let second_block_base_fee = 768592592;

    let _pending = seq_test_client
        .send_eth(
            random_wallet_address,
            None,
            None,
            None,
            // gas needed for transaction + 500 (to send) but this won't be enough for L1 fees
            21000 * second_block_base_fee + 500,
        )
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 1, None).await;

    let random_test_client = TestClient::new(
        seq_test_client.chain_id,
        random_wallet,
        random_wallet_address,
        seq_test_client.rpc_addr,
    )
    .await;

    let tx = random_test_client
        .send_eth_with_gas(
            Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            Some(0),
            Some(second_block_base_fee),
            21000,
            500,
        )
        .await
        .unwrap();

    let tx_from_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx.tx_hash(), Some(true))
        .await;

    assert!(tx_from_mempool.is_some());

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 2, None).await;

    let block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        block.header.base_fee_per_gas.unwrap(),
        second_block_base_fee
    );

    let tx_from_mempool = seq_test_client
        .eth_get_transaction_by_hash(*tx.tx_hash(), Some(true))
        .await;

    let soft_confirmation = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(block.header.number.unwrap())
        .await
        .unwrap();

    assert_eq!(block.transactions.len(), 0);
    assert!(tx_from_mempool.is_none());
    assert_eq!(soft_confirmation.txs.unwrap().len(), 1); // TODO: if we can also remove the tx from soft confirmation, that'd be very efficient

    wait_for_l2_block(&full_node_test_client, block.header.number.unwrap(), None).await;

    let block_from_full_node = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(block_from_full_node, block);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn sequencer_crash_restore_mempool() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::INFO);
    //
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let db_test_client =
        PostgresConnector::new_test_client("sequencer_crash_restore_mempool".to_owned())
            .await
            .unwrap();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);
    sequencer_config.mempool_conf = SequencerMempoolConfig {
        max_account_slots: 100,
        ..Default::default()
    };
    sequencer_config.db_config = Some(
        SharedBackupDbConfig::default().set_db_name("sequencer_crash_restore_mempool".to_owned()),
    );

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

    let txs = db_test_client.get_all_txs().await.unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0].tx_hash, tx_hash.to_vec());
    assert_eq!(txs[1].tx_hash, tx_hash2.to_vec());

    let signed_tx = Signed::<TxEip1559>::try_from(tx_1.clone()).unwrap();
    let envelope = TxEnvelope::Eip1559(signed_tx);
    let decoded = TxEnvelope::decode(&mut txs[0].tx.as_ref()).unwrap();
    assert_eq!(envelope, decoded);

    // crash and reopen and check if the txs are in the mempool
    seq_task.abort();

    let _ = copy_dir_recursive(
        &sequencer_db_dir,
        &storage_dir.path().join("sequencer_copy"),
    );

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let da_db_dir_cloned = da_db_dir.clone();
    let sequencer_db_dir = storage_dir.path().join("sequencer_copy").to_path_buf();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
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

    let txs = db_test_client.get_all_txs().await.unwrap();
    // should be removed from db
    assert_eq!(txs.len(), 0);

    seq_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_db_get_proof() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let psql_db_name = "test_db_get_proof".to_string();
    let db_test_client = PostgresConnector::new_test_client(psql_db_name.clone())
        .await
        .unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
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

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: Some(SharedBackupDbConfig::default().set_db_name(psql_db_name)),
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

    let prover_node_test_client = make_test_client(prover_node_port).await;
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    da_service.publish_test_block().await.unwrap();
    // Commitment
    wait_for_l1_block(&da_service, 3, None).await;
    // Proof
    wait_for_l1_block(&da_service, 4, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    wait_for_postgres_proofs(&db_test_client, 1, Some(Duration::from_secs(60))).await;

    let ledger_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(4)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 1);

    let db_state_transition = &db_proofs[0].state_transition.0;

    assert_eq!(
        db_state_transition.sequencer_da_public_key,
        ledger_proof.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_state_transition.sequencer_public_key,
        ledger_proof.state_transition.sequencer_public_key
    );
    assert_eq!(db_proofs[0].l1_tx_id, ledger_proof.l1_tx_id);

    match ledger_proof.proof {
        ProofRpcResponse::Full(p) => {
            assert_eq!(db_proofs[0].proof_type, ProofType::Full);
            assert_eq!(db_proofs[0].proof_data, p)
        }
        ProofRpcResponse::PublicInput(p) => {
            assert_eq!(db_proofs[0].proof_type, ProofType::PublicInput);
            assert_eq!(db_proofs[0].proof_data, p)
        }
    };

    seq_task.abort();
    prover_node_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn full_node_verify_proof_and_store() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
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

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;

    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: None,
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

    let prover_node_test_client = make_test_client(prover_node_port).await;

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
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 4, None).await;

    // submits with new da block, triggers commitment submission.
    da_service.publish_test_block().await.unwrap();
    // This is the above block created.
    wait_for_l1_block(&da_service, 3, None).await;
    // Commitment submitted
    wait_for_l1_block(&da_service, 4, None).await;

    // Full node sync commitment block
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        5,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_start_block_number, 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    assert_eq!(commitments[0].found_in_l1, 4);

    let fourth_block_hash = da_service.get_block_at(4).await.unwrap().header.hash;

    let commitments_hash = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(fourth_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    let prover_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(4)
        .await;

    // The proof will be in l1 block #5 because prover publishes it after the commitment and
    // in mock da submitting proof and commitments creates a new block.
    // For full node to see the proof, we publish another l2 block and now it will check #5 l1 block
    wait_for_l1_block(&da_service, 5, None).await;

    // Up until this moment, Full node has only seen 2 DA blocks.
    // We need to force it to sync up to 5th DA block.
    for i in 7..=8 {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&full_node_test_client, i, None).await;
    }

    // So the full node should see the proof in block 5
    wait_for_proof(&full_node_test_client, 5, Some(Duration::from_secs(60))).await;
    let full_node_proof = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(5)
        .await
        .unwrap();
    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(
        prover_proof.state_transition,
        full_node_proof[0].state_transition
    );

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap()
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_all_flow() {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let psql_db_name = "test_all_flow".to_owned();
    let db_test_client = PostgresConnector::new_test_client(psql_db_name.clone())
        .await
        .unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
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

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: Some(SharedBackupDbConfig::default().set_db_name(psql_db_name)),
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

    let prover_node_test_client = make_test_client(prover_node_port).await;

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
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 3, None).await;

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    // Submit commitment
    da_service.publish_test_block().await.unwrap();
    // Commitment
    wait_for_l1_block(&da_service, 3, None).await;
    // Proof
    wait_for_l1_block(&da_service, 4, None).await;
    // Full node sync - commitment DA
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 5, None).await;
    // Full node sync - Proof DA
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_start_block_number, 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    assert_eq!(commitments[0].found_in_l1, 4);

    let fourth_block_hash = da_service.get_block_at(4).await.unwrap().header.hash;

    let commitments_hash = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(fourth_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    let prover_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(4)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 1);
    assert_eq!(
        db_proofs[0].state_transition.0.sequencer_da_public_key,
        prover_proof.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_proofs[0].state_transition.0.sequencer_public_key,
        prover_proof.state_transition.sequencer_public_key
    );
    assert_eq!(db_proofs[0].l1_tx_id, prover_proof.l1_tx_id);

    // the proof will be in l1 block #5 because prover publishes it after the commitment and in mock da submitting proof and commitments creates a new block
    // For full node to see the proof, we publish another l2 block and now it will check #5 l1 block
    // 7th soft batch
    wait_for_l1_block(&da_service, 5, None).await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 7, None).await;

    // So the full node should see the proof in block 5
    wait_for_proof(&full_node_test_client, 5, Some(Duration::from_secs(120))).await;
    let full_node_proof = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(5)
        .await
        .unwrap();

    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(
        prover_proof.state_transition,
        full_node_proof[0].state_transition
    );

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap()
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    let balance = full_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(3e18 as u128));

    let balance = prover_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(3e18 as u128));

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    // 8th soft batch
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 8, None).await;

    // Submit a commitment
    da_service.publish_test_block().await.unwrap();
    // Commitment
    wait_for_l1_block(&da_service, 6, None).await;
    // Proof
    wait_for_l1_block(&da_service, 7, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        7,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(7)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    let prover_proof_data = prover_node_test_client
        .ledger_get_proof_by_slot_height(7)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 2);
    assert_eq!(
        db_proofs[1].state_transition.0.sequencer_da_public_key,
        prover_proof_data.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_proofs[1].state_transition.0.sequencer_public_key,
        prover_proof_data.state_transition.sequencer_public_key
    );

    // let full node see the proof
    for i in 9..13 {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&full_node_test_client, i, None).await;
    }

    wait_for_proof(&full_node_test_client, 8, Some(Duration::from_secs(120))).await;
    let full_node_proof_data = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(8)
        .await
        .unwrap();

    assert_eq!(prover_proof_data.proof, full_node_proof_data[0].proof);
    assert_eq!(
        prover_proof_data.state_transition,
        full_node_proof_data[0].state_transition
    );

    let balance = full_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(5e18 as u128));

    let balance = prover_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(5e18 as u128));

    for i in 1..=8 {
        // print statuses
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    wait_for_l2_block(&test_client, 14, None).await;
    assert_eq!(test_client.eth_block_number().await, 14);

    // Synced up to the latest block
    wait_for_l2_block(&full_node_test_client, 14, Some(Duration::from_secs(60))).await;
    assert!(full_node_test_client.eth_block_number().await >= 14);

    // Synced up to the latest commitment
    wait_for_l2_block(&prover_node_test_client, 9, Some(Duration::from_secs(60))).await;
    assert!(prover_node_test_client.eth_block_number().await >= 9);

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

/// Transactions with a high gas limit should be accounted for by using
/// their actual cumulative gas consumption to prevent them from reserving
/// whole blocks on their own.
#[tokio::test(flavor = "multi_thread")]
async fn test_gas_limit_too_high() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir: tempfile::TempDir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let full_node_db_dir = db_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let target_gas_limit: u64 = 30_000_000;
    let transfer_gas_limit = 21_000;
    let system_txs_gas_used = 385984;
    let tx_count = (target_gas_limit - system_txs_gas_used).div_ceil(transfer_gas_limit);
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let seq_da_dir = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            seq_da_dir,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            // Increase max account slots to not stuck as spammer
            Some(SequencerConfig {
                private_key: TEST_PRIVATE_KEY.to_string(),
                min_soft_confirmations_per_commitment: 1000,
                test_mode: true,
                deposit_mempool_fetch_limit: 100,
                mempool_conf: SequencerMempoolConfig {
                    max_account_slots: tx_count * 2,
                    ..Default::default()
                },
                db_config: Default::default(),
                da_update_interval_ms: 1000,
                block_production_interval_ms: 1000,
            }),
            Some(true),
            100,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            full_node_db_dir,
            da_db_dir_cloned,
            1000,
            true,
            None,
            None,
            Some(true),
            100,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    let mut tx_hashes = vec![];
    // Loop until tx_count.
    // This means that we are going to have 5 transactions which have not been included.
    for _ in 0..tx_count + 4 {
        let tx_hash = seq_test_client
            .send_eth_with_gas(addr, None, None, 10_000_000, 0u128)
            .await
            .unwrap();
        tx_hashes.push(tx_hash);
    }

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 1, Some(Duration::from_secs(60))).await;

    let block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions = block.transactions.as_hashes().unwrap();
    // assert the block contains all txs apart from the last 5
    for tx_hash in tx_hashes[0..tx_hashes.len() - 5].iter() {
        assert!(block_transactions.contains(tx_hash.tx_hash()));
    }
    for tx_hash in tx_hashes[tx_hashes.len() - 5..].iter() {
        assert!(!block_transactions.contains(tx_hash.tx_hash()));
    }

    let block_from_sequencer = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        block_from_sequencer.header.state_root,
        block.header.state_root
    );
    assert_eq!(block_from_sequencer.header.hash, block.header.hash);

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 2, None).await;

    let block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_from_sequencer = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(!block.transactions.is_empty());
    assert_eq!(
        block_from_sequencer.header.state_root,
        block.header.state_root
    );
    assert_eq!(block_from_sequencer.header.hash, block.header.hash);

    seq_task.abort();
    full_node_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_head_soft_batch() {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

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

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 2, None).await;

    let latest_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let head_soft_batch = seq_test_client
        .ledger_get_head_soft_batch()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest_block.header.number.unwrap(), 2);
    assert_eq!(
        head_soft_batch.post_state_root.as_slice(),
        latest_block.header.state_root.as_slice()
    );

    let head_soft_batch_height = seq_test_client
        .ledger_get_head_soft_batch_height()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_soft_batch_height, 2);

    seq_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_full_node_sync_status() {
    // citrea::initialize_logging();

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
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

    let seq_port = seq_port_rx.await.unwrap();

    let seq_test_client = init_test_rollup(seq_port).await;
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..300 {
        let _pending = seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    wait_for_l2_block(&seq_test_client, 300, Some(Duration::from_secs(60))).await;

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
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    wait_for_l2_block(&full_node_test_client, 5, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Syncing(syncing) => {
            println!("{:?}", syncing);
            assert!(syncing.synced_block_number > 0 && syncing.synced_block_number < 300);
            assert_eq!(syncing.head_block_number, 300);
        }
        _ => panic!("Expected syncing status"),
    }

    wait_for_l2_block(&full_node_test_client, 300, Some(Duration::from_secs(60))).await;

    let status = full_node_test_client.citrea_sync_status().await;

    match status {
        CitreaStatus::Synced(synced_up_to) => assert_eq!(synced_up_to, 300),
        _ => panic!("Expected synced status"),
    }

    seq_task.abort();
    full_node_task.abort();
}
