use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_sequencer::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use ethereum_types::{H256, U256};
use ethers::abi::Address;
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::{BlockNumberOrTag, TxHash};
use secp256k1::rand::thread_rng;
use shared_backup_db::{PostgresConnector, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec, MockHash};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::{ProverConfig, ProverGuestRunConfig};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_prover_config, create_default_sequencer_config, start_rollup, NodeMode,
};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT};

struct TestConfig {
    seq_min_soft_confirmations: u64,
    deposit_mempool_fetch_limit: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            seq_min_soft_confirmations: DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            deposit_mempool_fetch_limit: 10,
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

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            None,
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

    (
        seq_test_client,
        full_node_test_client,
        seq_task,
        full_node_task,
        Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
    )
}

#[tokio::test]
async fn test_soft_batch_save() -> Result<(), anyhow::Error> {
    let config = TestConfig::default();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            None,
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

    let full_node_task_2 = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx_2,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(full_node_port),
            None,
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

    let _ = execute_blocks(&seq_test_client, &full_node_test_client).await;

    sleep(Duration::from_secs(10)).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let full_node_block_2 = full_node_test_client_2
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_block.state_root, full_node_block.state_root);
    assert_eq!(full_node_block.state_root, full_node_block_2.state_root);
    assert_eq!(seq_block.hash, full_node_block.hash);
    assert_eq!(full_node_block.hash, full_node_block_2.hash);

    seq_task.abort();
    full_node_task.abort();
    full_node_task_2.abort();

    Ok(())
}

#[tokio::test]
async fn test_full_node_send_tx() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, addr) =
        initialize_test(Default::default()).await;

    let tx_hash = full_node_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_millis(2000)).await;

    let sq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(sq_block.transactions.contains(&tx_hash.tx_hash()));
    assert!(full_node_block.transactions.contains(&tx_hash.tx_hash()));
    assert_eq!(sq_block.state_root, full_node_block.state_root);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_delayed_sync_ten_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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
        seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            None,
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

    sleep(Duration::from_secs(10)).await;

    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;
    let full_node_block = full_node_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
        .await;

    assert_eq!(seq_block.state_root, full_node_block.state_root);
    assert_eq!(seq_block.hash, full_node_block.hash);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_e2e_same_block_sync() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(Default::default()).await;

    let _ = execute_blocks(&seq_test_client, &full_node_test_client).await;

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_close_and_reopen_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    // Remove temp db directories if they exist
    let _ = fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node_copy"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node"));

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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

    // starting full node with db path
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node"),
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
        seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    // wait for full node to sync
    sleep(Duration::from_secs(5)).await;

    // check if latest blocks are the same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 10);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 10);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    // close full node
    rollup_task.abort();

    sleep(Duration::from_secs(2)).await;

    // create 100 more blocks
    for _ in 0..100 {
        seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
        seq_test_client.send_publish_batch_request().await;
    }

    let da_service = MockDaService::new(MockAddress::from([0; 32]));
    da_service.publish_test_block().await.unwrap();

    // start full node again
    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(
        Path::new("demo_data_test_close_and_reopen_full_node"),
        Path::new("demo_data_test_close_and_reopen_full_node_copy"),
    );

    sleep(Duration::from_secs(5)).await;

    // spin up the full node again with the same data where it left of only with different path to not stuck on lock
    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node_copy"),
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    // TODO: There should be a better way to test this?
    sleep(Duration::from_secs(10)).await;

    let full_node_port = full_node_port_rx.await.unwrap();

    let full_node_test_client = make_test_client(full_node_port).await;

    // check if the latest block state roots are same
    let seq_last_block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 110);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 110);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node_copy")).unwrap();
    fs::remove_dir_all(Path::new("demo_data_test_close_and_reopen_full_node")).unwrap();

    seq_task.abort();
    rollup_task.abort();

    Ok(())
}

#[tokio::test]
async fn test_get_transaction_by_hash() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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

    let rollup_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            None,
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
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(true))
        .await
        .unwrap();
    // Should get with mempool_only false/none
    let tx2 = full_node_test_client
        .eth_get_transaction_by_hash(pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_none());
    assert!(tx2.block_hash.is_none());
    assert_eq!(tx1.hash, pending_tx1.tx_hash());
    assert_eq!(tx2.hash, pending_tx2.tx_hash());

    // sequencer should also be able to get them
    // Should get just by checking the pool
    let tx1 = seq_test_client
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(true))
        .await
        .unwrap();
    let tx2 = seq_test_client
        .eth_get_transaction_by_hash(pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_none());
    assert!(tx2.block_hash.is_none());
    assert_eq!(tx1.hash, pending_tx1.tx_hash());
    assert_eq!(tx2.hash, pending_tx2.tx_hash());

    seq_test_client.send_publish_batch_request().await;

    // wait for the full node to sync
    sleep(Duration::from_millis(2000)).await;

    // make sure txs are in the block
    let seq_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    assert!(seq_block.transactions.contains(&pending_tx1.tx_hash()));
    assert!(seq_block.transactions.contains(&pending_tx2.tx_hash()));

    // same operations after the block is published, both sequencer and full node should be able to get them.
    // should not get with mempool_only true because it checks the sequencer mempool only
    let non_existent_tx = full_node_test_client
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(true))
        .await;
    // this should be none because it is not in the mempool anymore
    assert!(non_existent_tx.is_none());

    let tx1 = full_node_test_client
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(false))
        .await
        .unwrap();
    let tx2 = full_node_test_client
        .eth_get_transaction_by_hash(pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_some());
    assert!(tx2.block_hash.is_some());
    assert_eq!(tx1.hash, pending_tx1.tx_hash());
    assert_eq!(tx2.hash, pending_tx2.tx_hash());

    // should not get with mempool_only true because it checks mempool only
    let none_existent_tx = seq_test_client
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(true))
        .await;
    // this should be none because it is not in the mempool anymore
    assert!(none_existent_tx.is_none());

    // In other cases should check the block and find the tx
    let tx1 = seq_test_client
        .eth_get_transaction_by_hash(pending_tx1.tx_hash(), Some(false))
        .await
        .unwrap();
    let tx2 = seq_test_client
        .eth_get_transaction_by_hash(pending_tx2.tx_hash(), None)
        .await
        .unwrap();
    assert!(tx1.block_hash.is_some());
    assert!(tx2.block_hash.is_some());
    assert_eq!(tx1.hash, pending_tx1.tx_hash());
    assert_eq!(tx2.hash, pending_tx2.tx_hash());

    // create random tx hash and make sure it returns None
    let random_tx_hash: TxHash = TxHash::random();
    assert!(seq_test_client
        .eth_get_transaction_by_hash(H256::from_slice(random_tx_hash.as_slice()), None)
        .await
        .is_none());
    assert!(full_node_test_client
        .eth_get_transaction_by_hash(H256::from_slice(random_tx_hash.as_slice()), None)
        .await
        .is_none());

    seq_task.abort();
    rollup_task.abort();
    Ok(())
}

#[tokio::test]
async fn test_soft_confirmations_on_different_blocks() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let da_service = MockDaService::new(MockAddress::default());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(Default::default()).await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    sleep(Duration::from_secs(2)).await;

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

    for _ in 1..=6 {
        seq_test_client.spam_publish_batch_request().await.unwrap();
    }

    sleep(Duration::from_secs(2)).await;

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

#[tokio::test]
async fn test_reopen_sequencer() -> Result<(), anyhow::Error> {
    // open, close without publishing blokcs
    // then reopen, publish some blocks without error
    // Remove temp db directories if they exist
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_sequencer_copy"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_sequencer"));

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            Some("demo_data_test_reopen_sequencer"),
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
    assert_eq!(block.number.unwrap().as_u64(), 0);

    // close sequencer
    seq_task.abort();

    sleep(Duration::from_secs(1)).await;

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(
        Path::new("demo_data_test_reopen_sequencer"),
        Path::new("demo_data_test_reopen_sequencer_copy"),
    );

    let da_service = MockDaService::new(MockAddress::from([0; 32]));
    da_service.publish_test_block().await.unwrap();

    sleep(Duration::from_secs(1)).await;

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            Some("demo_data_test_reopen_sequencer_copy"),
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
    assert_eq!(seq_last_block.state_root, block.state_root);
    assert_eq!(
        seq_last_block.number.unwrap().as_u64(),
        block.number.unwrap().as_u64()
    );

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    assert_eq!(
        seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await
            .number
            .unwrap()
            .as_u64(),
        2
    );

    fs::remove_dir_all(Path::new("demo_data_test_reopen_sequencer_copy")).unwrap();
    fs::remove_dir_all(Path::new("demo_data_test_reopen_sequencer")).unwrap();

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
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code(), None)
            .await?;
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .await?
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(42), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.await.unwrap().unwrap();
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
            sequencer_client.spam_publish_batch_request().await.unwrap();
        }

        sleep(Duration::from_secs(1)).await;
    }

    let da_service = MockDaService::new(MockAddress::from([0; 32]));
    da_service.publish_test_block().await.unwrap();

    {
        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..300 {
            sequencer_client
                .send_eth(addr, None, None, None, 0u128)
                .await
                .unwrap();
            sequencer_client.spam_publish_batch_request().await.unwrap();
        }
    }

    sleep(Duration::from_millis(5000)).await;

    let seq_last_block = sequencer_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.number.unwrap().as_u64(), 504);
    assert_eq!(full_node_last_block.number.unwrap().as_u64(), 504);

    assert_eq!(seq_last_block.state_root, full_node_last_block.state_root);
    assert_eq!(seq_last_block.hash, full_node_last_block.hash);

    Ok(())
}

#[tokio::test]
async fn test_soft_confirmations_status_one_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let da_service = MockDaService::new(MockAddress::default());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

    // TODO check status=trusted

    sleep(Duration::from_secs(2)).await;

    // publish new da block
    da_service.publish_test_block().await.unwrap();
    seq_test_client.send_publish_batch_request().await; // TODO https://github.com/chainwayxyz/citrea/issues/214
    seq_test_client.send_publish_batch_request().await; // TODO https://github.com/chainwayxyz/citrea/issues/214

    sleep(Duration::from_secs(2)).await;

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

#[tokio::test]
async fn test_soft_confirmations_status_two_l1() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let da_service = MockDaService::new(MockAddress::default());

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(TestConfig {
            seq_min_soft_confirmations: 3,
            deposit_mempool_fetch_limit: 10,
        })
        .await;

    // first publish a few blocks fast make it land in the same da block
    for _ in 1..=2 {
        seq_test_client.send_publish_batch_request().await;
    }

    sleep(Duration::from_secs(2)).await;

    // publish new da block
    da_service.publish_test_block().await.unwrap();

    for _ in 2..=6 {
        seq_test_client.send_publish_batch_request().await;
    }

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
    seq_test_client.send_publish_batch_request().await; // TODO https://github.com/chainwayxyz/citrea/issues/214
    seq_test_client.send_publish_batch_request().await; // TODO https://github.com/chainwayxyz/citrea/issues/214

    sleep(Duration::from_secs(2)).await;

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

#[tokio::test]
async fn test_prover_sync_with_commitments() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let da_service = MockDaService::new(MockAddress::default());

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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

    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            Some(create_default_prover_config()),
            NodeMode::Prover(seq_port),
            None,
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

    sleep(Duration::from_secs(2)).await;

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);

    da_service.publish_test_block().await.unwrap();

    seq_test_client.send_publish_batch_request().await;

    // sequencer commitment should be sent
    da_service.publish_test_block().await.unwrap();
    // start l1 height = 1, end = 2
    seq_test_client.send_publish_batch_request().await;

    // wait for prover to sync
    sleep(Duration::from_secs(5)).await;

    // prover should have synced all 4 l2 blocks
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(3)).await;

    // Still should have 4 blokcs there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    sleep(Duration::from_secs(3)).await;
    // Still should have 4 blokcs there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);
    da_service.publish_test_block().await.unwrap();

    // Commitment is sent right before the 9th block is published
    seq_test_client.send_publish_batch_request().await;

    // Wait for prover to sync
    sleep(Duration::from_secs(5)).await;
    // Should now have 8 blocks = 2 commitments of blocks 1-4 and 5-8
    assert_eq!(prover_node_test_client.eth_block_number().await, 8);

    // TODO: Also test with multiple commitments in single Mock DA Block
    seq_task.abort();
    prover_node_task.abort();
    Ok(())
}

#[tokio::test]
async fn test_reopen_prover() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover_copy2"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover_copy"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover"));

    let da_service = MockDaService::new(MockAddress::default());

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            Some(create_default_prover_config()),
            NodeMode::SequencerNode,
            None,
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

    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            Some(create_default_prover_config()),
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover"),
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

    sleep(Duration::from_secs(2)).await;

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);

    da_service.publish_test_block().await.unwrap();

    seq_test_client.send_publish_batch_request().await;

    // sequencer commitment should be sent
    da_service.publish_test_block().await.unwrap();
    // start l1 height = 1, end = 2
    seq_test_client.send_publish_batch_request().await;

    // wait for prover to sync
    sleep(Duration::from_secs(5)).await;

    // prover should have synced all 4 l2 blocks
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    prover_node_task.abort();
    let _ = copy_dir_recursive(
        Path::new("demo_data_test_reopen_prover"),
        Path::new("demo_data_test_reopen_prover_copy"),
    );

    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            Some(create_default_prover_config()),
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover_copy"),
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

    sleep(Duration::from_secs(2)).await;

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(3)).await;

    // Still should have 4 blokcs there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);

    prover_node_task.abort();

    sleep(Duration::from_secs(2)).await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;

    let _ = copy_dir_recursive(
        Path::new("demo_data_test_reopen_prover_copy"),
        Path::new("demo_data_test_reopen_prover_copy2"),
    );

    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            Some(create_default_prover_config()),
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover_copy2"),
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

    sleep(Duration::from_secs(3)).await;
    // Still should have 4 blokcs there are no commitments yet
    assert_eq!(prover_node_test_client.eth_block_number().await, 4);
    da_service.publish_test_block().await.unwrap();

    // Commitment is sent right before the 9th block is published
    seq_test_client.send_publish_batch_request().await;

    // Wait for prover to sync
    sleep(Duration::from_secs(5)).await;
    // Should now have 8 blocks = 2 commitments of blocks 1-4 and 5-8
    assert_eq!(prover_node_test_client.eth_block_number().await, 8);

    // TODO: Also test with multiple commitments in single Mock DA Block
    seq_task.abort();
    prover_node_task.abort();

    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover_copy2"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover_copy"));
    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_prover"));
    Ok(())
}

#[tokio::test]
async fn test_system_transactons() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    let system_contract_address =
        Address::from_str("0x3100000000000000000000000000000000000001").unwrap();
    let system_signer_address =
        Address::from_str("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead").unwrap();

    let da_service = MockDaService::new(MockAddress::default());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(Default::default()).await;

    // publish some blocks with system transactions
    for _ in 0..10 {
        for _ in 0..5 {
            seq_test_client.spam_publish_batch_request().await.unwrap();
        }

        da_service.publish_test_block().await.unwrap();
    }

    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(5)).await;

    // check block 1-6-11-16-21-26-31-36-41-46-51 has system transactions
    for i in 0..=10 {
        let block_num = 1 + i * 5;

        let block = full_node_test_client
            .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Number(block_num)))
            .await;

        if block_num == 1 {
            assert_eq!(block.transactions.len(), 3);

            let init_tx = &block.transactions[0];
            let set_tx = &block.transactions[1];

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
            assert_eq!(block.transactions.len(), 1);

            let tx = &block.transactions[0];

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
                ethers::types::Bytes::from(BitcoinLightClient::get_block_hash(i).to_vec()),
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

#[tokio::test]
async fn test_system_tx_effect_on_block_gas_limit() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();
    let da_service = MockDaService::new(MockAddress::default());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests-low-block-gas-limit"),
            BasicKernelGenesisPaths {
                chain_state:
                    "../test-data/genesis/integration-tests-low-block-gas-limit/chain_state.json"
                        .into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
            4,
            true,
            None,
            // Increase max account slots to not stuck as spammer
            Some(SequencerConfig {
                min_soft_confirmations_per_commitment: 1000,
                test_mode: true,
                deposit_mempool_fetch_limit: 10,
                mempool_conf: SequencerMempoolConfig {
                    max_account_slots: 100,
                    ..Default::default()
                },
                db_config: Default::default(),
            }),
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;
    // sys tx use L1BlockHash(43615 + 73581) + Bridge(298471) = 415667 gas
    // the block gas limit is 1_500_000 because the system txs gas limit is 1_500_000 (decided with @eyusufatik and @okkothejawa as bridge init takes 1M gas)

    // 1500000 - 415667 = 1084333 gas left in block
    // 1084333 / 21000 = 51,6... so 51 ether transfer transactions can be included in the block

    // send 51 ether transfer transactions
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..50 {
        seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
    }

    // 51th tx should be the last tx in the soft batch
    let last_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    // 52th tx should not be in soft batch
    let not_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let last_in_receipt = last_in_tx.unwrap().await.unwrap().unwrap();

    sleep(Duration::from_secs(2)).await;

    let initial_soft_batch = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(1)
        .await
        .unwrap();

    let last_tx_hash = last_in_receipt.transaction_hash;
    let last_tx_raw = seq_test_client
        .eth_get_transaction_by_hash(last_tx_hash, Some(false))
        .await
        .unwrap()
        .rlp();

    assert!(last_in_receipt.block_number.is_some());

    // last in tx byte array should be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_batch.clone().txs.unwrap()[0].tx.as_slice(),
        &last_tx_raw
    )
    .is_some());

    seq_test_client.send_publish_batch_request().await;

    da_service.publish_test_block().await.unwrap();

    let not_in_receipt = not_in_tx.unwrap().await.unwrap().unwrap();

    let not_in_hash = not_in_receipt.transaction_hash;

    let not_in_raw = seq_test_client
        .eth_get_transaction_by_hash(not_in_hash, Some(false))
        .await
        .unwrap()
        .rlp();

    // not in tx byte array should not be a subarray of txs[0]
    assert!(find_subarray(
        initial_soft_batch.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw
    )
    .is_none());

    seq_test_client.send_publish_batch_request().await;

    let second_soft_batch = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(2)
        .await
        .unwrap();

    // should be in tx byte array of the soft batch after
    assert!(find_subarray(second_soft_batch.txs.unwrap()[0].tx.as_slice(), &not_in_raw).is_some());

    let block1 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
        .await;

    // the last in tx should be in the block
    assert!(block1.transactions.iter().any(|tx| tx == &last_tx_hash));
    // and the other tx should not be in
    assert!(!block1.transactions.iter().any(|tx| tx == &not_in_hash));

    let block2 = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Number(2)))
        .await;
    // the other tx should be in second block
    assert!(block2.transactions.iter().any(|tx| tx == &not_in_hash));

    seq_task.abort();

    Ok(())
}

fn find_subarray(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[tokio::test]
async fn sequencer_crash_and_replace_full_node() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();

    // open, close without publishing blokcs
    // then reopen, publish some blocks without error
    // Remove temp db directories if they exist
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_full_node"));
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_full_node_copy"));

    let db_test_client = PostgresConnector::new_test_client().await.unwrap();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    sequencer_config.db_config = Some(SharedBackupDbConfig::default());

    let da_service = MockDaService::with_finality(MockAddress::from([0; 32]), 2);
    da_service.publish_test_block().await.unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            None,
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
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::FullNode(seq_port),
            Some("demo_data_sequencer_full_node"),
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

    // second da block
    da_service.publish_test_block().await.unwrap();

    // before this the commitment will be sent
    // the commitment will be only in the first block so it is still not finalized
    // so the full node won't see the commitment
    seq_test_client.send_publish_batch_request().await;

    // wait for sync
    sleep(Duration::from_secs(2)).await;

    // should be synced
    assert_eq!(full_node_test_client.eth_block_number().await, 5);

    // assume sequencer craashed
    seq_task.abort();
    sleep(Duration::from_secs(2)).await;

    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 1);

    full_node_task.abort();

    sleep(Duration::from_secs(1)).await;

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    // Copy the db to a new path with the same contents because
    // the lock is not released on the db directory even though the task is aborted
    let _ = copy_dir_recursive(
        Path::new("demo_data_sequencer_full_node"),
        Path::new("demo_data_sequencer_full_node_copy"),
    );

    sleep(Duration::from_secs(1)).await;
    let config1 = sequencer_config.clone();
    // Start the full node as sequencer
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            Some("demo_data_sequencer_full_node_copy"),
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

    da_service.publish_test_block().await.unwrap();
    // new commitment will be sent here, it should send between 2 and 3 should not include 1
    seq_test_client.send_publish_batch_request().await;

    sleep(Duration::from_secs(5)).await;
    let commitments = db_test_client.get_all_commitments().await.unwrap();
    assert_eq!(commitments.len(), 2);
    assert_eq!(commitments[0].l1_start_height, 1);
    assert_eq!(commitments[0].l1_end_height, 1);
    assert_eq!(commitments[1].l1_start_height, 2);
    assert_eq!(commitments[1].l1_end_height, 3);

    let _ = fs::remove_dir_all(Path::new("demo_data_test_reopen_sequencer"));
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_full_node"));
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_full_node_copy"));

    seq_task.abort();

    Ok(())
}

#[tokio::test]
async fn transaction_failing_on_l1_is_removed_from_mempool() -> Result<(), anyhow::Error> {
    citrea::initialize_logging();

    let (seq_test_client, full_node_test_client, seq_task, full_node_task, _) =
        initialize_test(Default::default()).await;

    let random_wallet = LocalWallet::new(&mut thread_rng()).with_chain_id(seq_test_client.chain_id);

    let random_wallet_address = random_wallet.address();

    let second_block_base_fee: u64 = 768809031;

    seq_test_client
        .send_eth(
            random_wallet_address,
            None,
            None,
            None,
            // gas needed for transaction + 500 (to send) but this won't be enough for L1 fees
            (21000 * second_block_base_fee + 500) as u128,
        )
        .await
        .unwrap();

    seq_test_client.send_publish_batch_request().await;

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
        .eth_get_transaction_by_hash(tx.tx_hash(), Some(true))
        .await;

    assert!(tx_from_mempool.is_some());

    seq_test_client.send_publish_batch_request().await;

    let block = seq_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(
        block.base_fee_per_gas.unwrap(),
        U256::from(second_block_base_fee)
    );

    let tx_from_mempool = seq_test_client
        .eth_get_transaction_by_hash(tx.tx_hash(), Some(true))
        .await;

    let soft_confirmation = seq_test_client
        .ledger_get_soft_batch_by_number::<MockDaSpec>(block.number.unwrap().as_u64())
        .await
        .unwrap();

    assert_eq!(block.transactions.len(), 0);
    assert!(tx_from_mempool.is_none());
    assert_eq!(soft_confirmation.txs.unwrap().len(), 1); // TODO: if we can also remove the tx from soft confirmation, that'd be very efficient

    sleep(Duration::from_secs(2)).await;

    let block_from_full_node = full_node_test_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(block_from_full_node, block);

    seq_task.abort();
    full_node_task.abort();

    Ok(())
}

#[tokio::test]
async fn sequencer_crash_restore_mempool() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging();
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_restore_mempool"));
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_restore_mempool_copy"));

    let db_test_client = PostgresConnector::new_test_client().await.unwrap();

    let mut sequencer_config = create_default_sequencer_config(4, Some(true), 10);

    sequencer_config.db_config = Some(SharedBackupDbConfig::default());

    let da_service = MockDaService::with_finality(MockAddress::from([0; 32]), 2);
    da_service.publish_test_block().await.unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            Some("demo_data_sequencer_restore_mempool"),
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

    let tx_hash = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap()
        .tx_hash();

    let tx_hash2 = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await
        .unwrap()
        .tx_hash();

    let tx_1 = seq_test_client
        .eth_get_transaction_by_hash(tx_hash, Some(true))
        .await
        .unwrap();
    let tx_2 = seq_test_client
        .eth_get_transaction_by_hash(tx_hash2, Some(true))
        .await
        .unwrap();

    assert_eq!(tx_1.hash, tx_hash);
    assert_eq!(tx_2.hash, tx_hash2);

    let txs = db_test_client.get_all_txs().await.unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0].tx_hash, tx_hash.as_bytes().to_vec());
    assert_eq!(txs[1].tx_hash, tx_hash2.as_bytes().to_vec());

    assert_eq!(txs[0].tx, tx_1.rlp().to_vec());

    // crash and reopen and check if the txs are in the mempool
    seq_task.abort();

    let _ = copy_dir_recursive(
        Path::new("demo_data_sequencer_restore_mempool"),
        Path::new("demo_data_sequencer_restore_mempool_copy"),
    );

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let config1 = sequencer_config.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state: "../test-data/genesis/integration-tests/chain_state.json".into(),
            },
            None,
            NodeMode::SequencerNode,
            Some("demo_data_sequencer_restore_mempool_copy"),
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
        .eth_get_transaction_by_hash(tx_hash, Some(true))
        .await
        .unwrap();
    let tx_2_mempool = seq_test_client
        .eth_get_transaction_by_hash(tx_hash2, Some(true))
        .await
        .unwrap();

    assert_eq!(tx_1_mempool, tx_1);
    assert_eq!(tx_2_mempool, tx_2);

    // publish block and check if the txs are deleted from pg
    seq_test_client.send_publish_batch_request().await;
    // should be removed from mempool
    assert!(seq_test_client
        .eth_get_transaction_by_hash(tx_hash, Some(true))
        .await
        .is_none());
    assert!(seq_test_client
        .eth_get_transaction_by_hash(tx_hash2, Some(true))
        .await
        .is_none());

    let txs = db_test_client.get_all_txs().await.unwrap();
    // should be removed from db
    assert_eq!(txs.len(), 0);

    seq_task.abort();
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_restore_mempool"));
    let _ = fs::remove_dir_all(Path::new("demo_data_sequencer_restore_mempool_copy"));

    Ok(())
}
