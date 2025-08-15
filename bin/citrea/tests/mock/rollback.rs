#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use alloy_primitives::{Address, U256};
use alloy_rpc_types::{BlockId, BlockNumberOrTag};
use citrea_common::{BatchProverConfig, NodeType, SequencerConfig};
use citrea_stf::genesis_config::GenesisPaths;
use citrea_storage_ops::rollback::Rollback;
use futures::FutureExt;
use reth_tasks::TaskManager;
use sov_db::ledger_db::migrations::copy_db_dir_recursive;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    CommitmentIndicesByL1, VerifiedBatchProofsBySlotNumber, BATCH_PROVER_LEDGER_TABLES,
    FULL_NODE_LEDGER_TABLES, SEQUENCER_LEDGER_TABLES,
};
use sov_db::schema::types::SlotNumber;
use sov_db::state_db::StateDB;
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::SequencerCommitmentResponse;

use crate::common::client::TestClient;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, wait_for_proof, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};
use crate::mock::evm::init_test_rollup;

fn instantiate_dbs(
    db_path: &Path,
    tables: &[&str],
) -> anyhow::Result<(LedgerDB, Arc<sov_schema_db::DB>, Arc<sov_schema_db::DB>)> {
    let tables = tables.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let rocksdb_config = RocksdbConfig::new(db_path, None, Some(tables.to_vec()));
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = Arc::new(NativeDB::setup_schema_db(&rocksdb_config)?);
    let state_db = Arc::new(StateDB::setup_schema_db(&rocksdb_config)?);

    Ok((ledger_db, native_db, state_db))
}

async fn start_sequencer(
    sequencer_db_dir: &Path,
    da_db_dir: &Path,
    restart: bool,
) -> (TaskManager, Box<TestClient>, SocketAddr) {
    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: 10,
        test_mode: true,
        ..Default::default()
    };
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let rollup_config = create_default_rollup_config(
        true,
        sequencer_db_dir,
        da_db_dir,
        NodeMode::SequencerNode,
        None,
    );

    let seq_task_manager = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        restart,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = if restart {
        make_test_client(seq_port).await.unwrap()
    } else {
        init_test_rollup(seq_port).await
    };

    (seq_task_manager, seq_test_client, seq_port)
}

async fn start_full_node(
    full_node_db_dir: &Path,
    da_db_dir: &Path,
    seq_port: SocketAddr,
    restart: bool,
) -> (TaskManager, Box<TestClient>) {
    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();
    let rollup_config = create_default_rollup_config(
        true,
        full_node_db_dir,
        da_db_dir,
        NodeMode::FullNode(seq_port),
        None,
    );
    let full_node_task_manager = start_rollup(
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
    let full_node_test_client = if restart {
        make_test_client(full_node_port).await.unwrap()
    } else {
        init_test_rollup(full_node_port).await
    };

    (full_node_task_manager, full_node_test_client)
}

async fn start_batch_prover(
    batch_prover_db_dir: &Path,
    da_db_dir: &Path,
    seq_port: SocketAddr,
    restart: bool,
) -> (TaskManager, Box<TestClient>) {
    let (batch_prover_port_tx, batch_prover_port_rx) = tokio::sync::oneshot::channel();
    let rollup_config = create_default_rollup_config(
        true,
        batch_prover_db_dir,
        da_db_dir,
        NodeMode::Prover(seq_port),
        None,
    );
    let batch_prover_task_manager = start_rollup(
        batch_prover_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        Some(BatchProverConfig {
            proving_mode: citrea_common::ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
        }),
        None,
        rollup_config,
        None,
        None,
        false,
    )
    .await;

    let batch_prover_port = batch_prover_port_rx.await.unwrap();
    let batch_prover_test_client = if restart {
        make_test_client(batch_prover_port).await.unwrap()
    } else {
        init_test_rollup(batch_prover_port).await
    };

    (batch_prover_task_manager, batch_prover_test_client)
}

async fn rollback_node(
    node_type: NodeType,
    tables: &[&str],
    old_path: &Path,
    new_path: &Path,
    rollback_l2_height: u64,
    rollback_l1_height: u64,
    commitment_index: u32,
) -> anyhow::Result<()> {
    copy_db_dir_recursive(old_path, new_path).unwrap();

    let (ledger_db, native_db, state_db) = instantiate_dbs(new_path, tables).unwrap();
    let rollback = Rollback::new(ledger_db.inner(), state_db.clone(), native_db.clone());

    rollback
        .execute(
            node_type,
            Some(rollback_l2_height),
            Some(rollback_l1_height),
            Some(commitment_index),
        )
        .await
        .unwrap();

    drop(rollback);
    drop(state_db);
    drop(native_db);
    drop(ledger_db);

    Ok(())
}

async fn fill_blocks(
    test_client: &TestClient,
    da_service: &MockDaService,
    addr: &Address,
    fullnode_test_client: Option<&TestClient>,
) {
    for i in 1..=50 {
        // send one ether to some address
        let _ = test_client
            .send_eth(*addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        test_client.spam_publish_batch_request().await.unwrap();

        if i % 10 == 0 {
            wait_for_l2_block(test_client, i, None).await;
            wait_for_l1_block(da_service, 3 + (i / 10), None).await;
            if let Some(fullnode_test_client) = fullnode_test_client {
                wait_for_proof(fullnode_test_client, 3 + ((i / 10) * 2), None).await;
            }
        }
    }
}

async fn assert_dbs(
    test_client: &TestClient,
    addr: Address,
    check_l1_block: Option<u64>,
    check_l2_block: u64,
    balance_at_l2_height: u128,
) {
    // Check l2 blocks have been rolled back in Ledger DB
    wait_for_l2_block(test_client, check_l2_block, None).await;

    // Suppress output of panics
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    // Check state DB is rolled back.
    let get_balance_result = test_client
        .eth_get_balance(
            addr,
            Some(BlockId::Number(BlockNumberOrTag::Number(check_l2_block))),
        )
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(balance_at_l2_height)
    );

    // Check native DB is rolled back
    let check_block_by_number_result =
        AssertUnwindSafe(test_client.eth_get_block_by_number_with_detail(Some(
            BlockNumberOrTag::Number(check_l2_block + 1),
        )))
        .catch_unwind()
        .await;
    assert!(check_block_by_number_result.is_err());
    panic::set_hook(prev_hook);

    // Should NOT panic as the data we're requesting here is correct
    test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(check_l2_block)))
        .await;

    let Some(check_l1_block) = check_l1_block else {
        return;
    };
    let commitments: Vec<SequencerCommitmentResponse> = test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(check_l1_block)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);
}

/// Trigger rollback DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_rollback() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let (seq_task_manager, seq_test_client, _seq_port) =
        start_sequencer(&sequencer_db_dir, &da_db_dir, false).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    fill_blocks(&seq_test_client, &da_service, &addr, None).await;

    wait_for_l2_block(&seq_test_client, 50, None).await;

    let get_balance_result = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    seq_task_manager.graceful_shutdown();

    // rollback 10 L2 blocks
    let rollback_l2_height = 30;
    // We have 8 L1 blocks by now and we want to rollback
    // the last one.
    let rollback_l1_height = 6;
    let rollback_index = 1;
    let new_sequencer_db_dir = storage_dir.path().join("sequencer2").to_path_buf();
    rollback_node(
        NodeType::Sequencer,
        SEQUENCER_LEDGER_TABLES,
        &sequencer_db_dir,
        &new_sequencer_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    let (seq_task_manager, seq_test_client, _) =
        start_sequencer(&new_sequencer_db_dir, &da_db_dir, true).await;

    assert_dbs(&seq_test_client, addr, None, 30, 30000000000000000000).await;

    seq_task_manager.graceful_shutdown();

    Ok(())
}

/// Trigger rollback DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_fullnode_rollback() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let full_node_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    //------------------
    // Start nodes
    //------------------
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&sequencer_db_dir, &da_db_dir, false).await;

    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&full_node_db_dir, &da_db_dir, seq_port, false).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    //------------------
    // Fill blocks
    //------------------
    fill_blocks(&seq_test_client, &da_service, &addr, None).await;

    wait_for_l2_block(&seq_test_client, 50, None).await;
    wait_for_l2_block(&full_node_test_client, 50, None).await;

    //------------------
    // Assert data
    //------------------
    let get_balance_result = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();

    //------------------
    // Rollback
    //------------------
    // rollback 10 L2 blocks
    let rollback_l2_height = 30;
    // We have 8 L1 blocks by now and we want to rollback
    // the last one.
    let rollback_l1_height = 6;
    let rollback_index = 1;

    let new_sequencer_db_dir = storage_dir.path().join("sequencer2").to_path_buf();
    rollback_node(
        NodeType::Sequencer,
        SEQUENCER_LEDGER_TABLES,
        &sequencer_db_dir,
        &new_sequencer_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    //------------------
    // Assert state after rollback
    //------------------
    let new_full_node_db_dir = storage_dir.path().join("full-node2").to_path_buf();
    rollback_node(
        NodeType::FullNode,
        FULL_NODE_LEDGER_TABLES,
        &full_node_db_dir,
        &new_full_node_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    //------------------
    // Make sure nodes are able to sync after rollback
    //------------------
    let new_sequencer_db_dir = storage_dir.path().join("sequencer3").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("sequencer2"),
        &new_sequencer_db_dir,
    )
    .unwrap();
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&new_sequencer_db_dir, &da_db_dir, true).await;

    let new_full_node_db_dir = storage_dir.path().join("full-node3").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("full-node2"),
        &new_full_node_db_dir,
    )
    .unwrap();
    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&new_full_node_db_dir, &da_db_dir, seq_port, true).await;

    assert_dbs(
        &full_node_test_client,
        addr,
        Some(rollback_l1_height),
        30,
        30000000000000000000,
    )
    .await;

    for _ in 0..10 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }
    wait_for_l2_block(&seq_test_client, 40, None).await;
    wait_for_l2_block(&full_node_test_client, 40, None).await;

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();

    Ok(())
}

/// Trigger rollback DB data.
/// This test makes sure that a rollback on fullnode without rolling back sequencer
/// enables fullnode to sync from the rollback point up until latest sequencer block.
#[tokio::test(flavor = "multi_thread")]
async fn test_fullnode_rollback_without_sequencer_rollback() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let full_node_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    //------------------
    // Start nodes
    //------------------
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&sequencer_db_dir, &da_db_dir, false).await;

    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&full_node_db_dir, &da_db_dir, seq_port, false).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    //------------------
    // Fill blocks
    //------------------
    fill_blocks(&seq_test_client, &da_service, &addr, None).await;

    wait_for_l2_block(&seq_test_client, 50, None).await;
    wait_for_l2_block(&full_node_test_client, 50, None).await;

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();

    //------------------
    // Rollback
    //------------------
    // rollback 10 L2 blocks
    let rollback_l2_height = 30;
    // We have 8 L1 blocks by now and we want to rollback
    // the last one.
    let rollback_l1_height = 6;
    let rollback_index = 1;

    let new_full_node_db_dir = storage_dir.path().join("full-node2").to_path_buf();
    rollback_node(
        NodeType::FullNode,
        FULL_NODE_LEDGER_TABLES,
        &full_node_db_dir,
        &new_full_node_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    //------------------
    // Make sure nodes are able to sync after rollback
    //------------------
    let new_sequencer_db_dir = storage_dir.path().join("sequencer2").to_path_buf();
    copy_db_dir_recursive(&sequencer_db_dir, &new_sequencer_db_dir).unwrap();
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&new_sequencer_db_dir, &da_db_dir, true).await;

    let new_full_node_db_dir = storage_dir.path().join("full-node3").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("full-node2"),
        &new_full_node_db_dir,
    )
    .unwrap();
    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&new_full_node_db_dir, &da_db_dir, seq_port, true).await;

    for _ in 0..10 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }
    wait_for_l2_block(&seq_test_client, 40, None).await;
    wait_for_l2_block(&full_node_test_client, 40, None).await;

    let sequencer_head_l2 = seq_test_client.ledger_get_head_l2_block().await;

    let seq_l2_block = sequencer_head_l2.unwrap().unwrap();

    wait_for_l2_block(
        &full_node_test_client,
        seq_l2_block.header.height.to::<u64>(),
        None,
    )
    .await;

    let full_node_head_l2 = full_node_test_client.ledger_get_head_l2_block().await;

    let full_node_l2_block = full_node_head_l2.unwrap().unwrap();

    assert_eq!(
        seq_l2_block.header.state_root,
        full_node_l2_block.header.state_root
    );

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();

    Ok(())
}

/// Trigger rollback DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_batch_prover_rollback() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node", "batch-prover"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let full_node_db_dir = storage_dir.path().join("full-node").to_path_buf();
    let batch_prover_db_dir = storage_dir.path().join("batch-prover").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    //------------------
    // Start nodes
    //------------------
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&sequencer_db_dir, &da_db_dir, false).await;

    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&full_node_db_dir, &da_db_dir, seq_port, false).await;

    let (batch_prover_task_manager, batch_prover_test_client) =
        start_batch_prover(&batch_prover_db_dir, &da_db_dir, seq_port, false).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    fill_blocks(
        &seq_test_client,
        &da_service,
        &addr,
        Some(&full_node_test_client),
    )
    .await;

    wait_for_l2_block(&full_node_test_client, 50, None).await;
    wait_for_l2_block(&batch_prover_test_client, 50, None).await;

    //------------------
    // Assert sequencer state
    //------------------
    let get_balance_result = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    let get_balance_result = full_node_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    let get_balance_result = batch_prover_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Number(50))))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(50000000000000000000u128)
    );

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();
    batch_prover_task_manager.graceful_shutdown();

    //------------------
    // Assert fullnode state
    //------------------
    let new_full_node_db_dir = storage_dir.path().join("full-node2").to_path_buf();
    copy_db_dir_recursive(&full_node_db_dir, &new_full_node_db_dir).unwrap();

    let new_batch_prover_db_dir = storage_dir.path().join("batch-prover2").to_path_buf();
    copy_db_dir_recursive(&batch_prover_db_dir, &new_batch_prover_db_dir).unwrap();

    // At block 22, full node SHOULD have a verified proof
    let (ledger_db, _native_db, _state_db) =
        instantiate_dbs(&new_full_node_db_dir, FULL_NODE_LEDGER_TABLES).unwrap();
    let ledger_db = ledger_db.inner();
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(7))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(9))
        .unwrap()
        .is_some());

    // rollback 10 L2 blocks
    let rollback_l2_height = 30;
    // We have 9 L1 blocks by now and we want to rollback.
    let rollback_l1_height = 9;
    let rollback_index = 1;

    let new_full_node_db_dir = storage_dir.path().join("full-node3").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("full-node2"),
        &new_full_node_db_dir,
    )
    .unwrap();
    let new_batch_prover_db_dir = storage_dir.path().join("batch-prover3").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("batch-prover2"),
        &new_batch_prover_db_dir,
    )
    .unwrap();

    //------------------
    // Rollback nodes
    //------------------
    let new_sequencer_db_dir = storage_dir.path().join("sequencer3").to_path_buf();
    rollback_node(
        NodeType::Sequencer,
        SEQUENCER_LEDGER_TABLES,
        &sequencer_db_dir,
        &new_sequencer_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    rollback_node(
        NodeType::FullNode,
        FULL_NODE_LEDGER_TABLES,
        &full_node_db_dir,
        &new_full_node_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    rollback_node(
        NodeType::BatchProver,
        BATCH_PROVER_LEDGER_TABLES,
        &batch_prover_db_dir,
        &new_batch_prover_db_dir,
        rollback_l2_height,
        rollback_l1_height,
        rollback_index,
    )
    .await
    .unwrap();

    //------------------
    // Assert state after rollback
    //------------------
    let new_sequencer_db_dir = storage_dir.path().join("sequencer4").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("sequencer3"),
        &new_sequencer_db_dir,
    )
    .unwrap();
    let new_full_node_db_dir = storage_dir.path().join("full-node4").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("full-node3"),
        &new_full_node_db_dir,
    )
    .unwrap();
    let new_batch_prover_db_dir = storage_dir.path().join("batch-prover4").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("batch-prover3"),
        &new_batch_prover_db_dir,
    )
    .unwrap();

    // At block 11, verified proof in full node should have been pruned.
    let (fn_ledger_db, _, _) =
        instantiate_dbs(&new_full_node_db_dir, FULL_NODE_LEDGER_TABLES).unwrap();
    let fn_ledger_db = fn_ledger_db.inner();
    assert!(fn_ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(9))
        .unwrap()
        .is_some());
    assert!(fn_ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(11))
        .unwrap()
        .is_none());

    // At block 11, verified proof in prover should have been pruned.
    let (bp_ledger_db, _, _) =
        instantiate_dbs(&new_batch_prover_db_dir, BATCH_PROVER_LEDGER_TABLES).unwrap();
    let bp_ledger_db = bp_ledger_db.inner();
    assert!(bp_ledger_db
        .get::<CommitmentIndicesByL1>(&SlotNumber(8))
        .unwrap()
        .is_some());
    assert!(bp_ledger_db
        .get::<CommitmentIndicesByL1>(&SlotNumber(10))
        .unwrap()
        .is_none());

    //------------------
    // Start nodes and make sure they are able to sync
    //------------------
    let new_sequencer_db_dir = storage_dir.path().join("sequencer5").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("sequencer4"),
        &new_sequencer_db_dir,
    )
    .unwrap();
    let (seq_task_manager, seq_test_client, seq_port) =
        start_sequencer(&new_sequencer_db_dir, &da_db_dir, true).await;

    let new_full_node_db_dir = storage_dir.path().join("full-node5").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("full-node4"),
        &new_full_node_db_dir,
    )
    .unwrap();
    let (full_node_task_manager, full_node_test_client) =
        start_full_node(&new_full_node_db_dir, &da_db_dir, seq_port, true).await;

    let new_batch_prover_db_dir = storage_dir.path().join("batch-prover5").to_path_buf();
    copy_db_dir_recursive(
        &storage_dir.path().join("batch-prover4"),
        &new_batch_prover_db_dir,
    )
    .unwrap();
    let (batch_prover_task_manager, batch_prover_test_client) =
        start_batch_prover(&new_batch_prover_db_dir, &da_db_dir, seq_port, true).await;

    assert_dbs(
        &batch_prover_test_client,
        addr,
        None,
        30,
        30000000000000000000,
    )
    .await;

    for _ in 0..10 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }
    wait_for_l2_block(&seq_test_client, 40, None).await;
    wait_for_l2_block(&full_node_test_client, 40, None).await;
    wait_for_l2_block(&batch_prover_test_client, 40, None).await;

    seq_task_manager.graceful_shutdown();
    full_node_task_manager.graceful_shutdown();
    batch_prover_task_manager.graceful_shutdown();

    Ok(())
}
