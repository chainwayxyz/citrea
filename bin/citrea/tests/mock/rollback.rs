use std::fs;
use std::panic::AssertUnwindSafe;
use std::str::FromStr;
use std::sync::Arc;

use alloy_primitives::{Address, U256};
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use citrea_storage_ops::pruning::types::StorageNodeType;
use citrea_storage_ops::rollback::Rollback;
use futures::FutureExt;
use reth_primitives::{BlockId, BlockNumberOrTag};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::SEQUENCER_LEDGER_TABLES;
use sov_db::state_db::StateDB;
use sov_mock_da::{MockAddress, MockDaService};

use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};
use crate::mock::evm::init_test_rollup;

/// Trigger rollback native DB data.
#[tokio::test(flavor = "multi_thread")]
async fn test_sequencer_rollback() -> Result<(), anyhow::Error> {
    citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let da_service = MockDaService::new(MockAddress::default(), &da_db_dir.clone());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }
    wait_for_l1_block(&da_service, 3, None).await;

    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: 10,
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

    let sequencer_config1 = sequencer_config.clone();
    let task_manager = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config1),
        None,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    for i in 1..=50 {
        // send one ether to some address
        let _ = seq_test_client
            .send_eth(addr, None, None, None, 1e18 as u128)
            .await
            .unwrap();

        seq_test_client.spam_publish_batch_request().await.unwrap();

        if i % 5 == 0 {
            wait_for_l2_block(&seq_test_client, i, None).await;

            // Get the hash of the latest block
            seq_test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Number(i)))
                .await
                .header
                .hash;

            da_service.publish_test_block().await.unwrap();

            wait_for_l1_block(&da_service, 3 + (i / 5), None).await;
        }
    }

    task_manager.abort().await;

    fs::remove_file(format!("{}/ledger/LOCK", sequencer_db_dir.display())).unwrap();

    let sequencer_tables = SEQUENCER_LEDGER_TABLES
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();
    let rocksdb_config =
        RocksdbConfig::new(&sequencer_db_dir, None, Some(sequencer_tables.to_vec()));
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let native_db = Arc::new(NativeDB::setup_schema_db(&rocksdb_config)?);
    let state_db = Arc::new(StateDB::setup_schema_db(&rocksdb_config)?);
    let rollback = Rollback::new(ledger_db.inner(), state_db.clone(), native_db.clone());

    // rollback 10 L2 blocks
    let rollback_to_l2 = 40;
    // We have 13 L1 blocks by now and we want to rollback
    // the last 2.
    let rollback_to_l1 = 11;
    rollback
        .execute(
            StorageNodeType::Sequencer,
            50,
            rollback_to_l2,
            rollback_to_l1,
        )
        .await
        .unwrap();

    drop(rollback);
    drop(state_db);
    drop(native_db);
    drop(ledger_db);

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();
    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
            None,
        )
        .await;
    });
    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await.unwrap();

    // Check soft confirmations have been rolled back in Ledger DB
    wait_for_l2_block(&seq_test_client, 40, None).await;

    // Check state DB is rolled back.
    let get_balance_result = seq_test_client
        .eth_get_balance(addr, Some(BlockId::Number(BlockNumberOrTag::Latest)))
        .await;
    assert!(get_balance_result.is_ok());
    assert_eq!(
        get_balance_result.unwrap(),
        U256::from(40000000000000000000u128)
    );

    // Check native DB is rolled back
    let check_block_by_number_result = AssertUnwindSafe(
        seq_test_client.eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(41))),
    )
    .catch_unwind()
    .await;
    assert!(check_block_by_number_result.is_err());

    // Should NOT panic as the data we're requesting here is correct
    seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(40)))
        .await;

    seq_task.abort();

    Ok(())
}
