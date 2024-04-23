use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_evm::system_contracts::L1BlockHashList;
use citrea_sequencer::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use ethereum_types::H256;
use ethers::abi::Address;
use reth_primitives::{BlockNumberOrTag, TxHash};
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec, MockHash};
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::RollupProverConfig;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{start_rollup, NodeMode};
use crate::DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT;

struct TestConfig {
    seq_min_soft_confirmations: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            seq_min_soft_confirmations: DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(full_node_port),
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            false,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node"),
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            Some("demo_data_test_close_and_reopen_full_node_copy"),
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::FullNode(seq_port),
            None,
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            Some("demo_data_test_reopen_sequencer"),
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            Some("demo_data_test_reopen_sequencer_copy"),
            DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            4,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::Prover(seq_port),
            None,
            4,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            4,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover"),
            4,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover_copy"),
            4,
            true,
            None,
            None,
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
            RollupProverConfig::Execute,
            NodeMode::Prover(seq_port),
            Some("demo_data_test_reopen_prover_copy2"),
            4,
            true,
            None,
            None,
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
    let l1_blockhash_contract = L1BlockHashList::default();

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
            assert_eq!(block.transactions.len(), 2);

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
                l1_blockhash_contract.get_block_hash(i),
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
    let l1_blockhash_contract = L1BlockHashList::default();

    let system_contract_address =
        Address::from_str("0x3100000000000000000000000000000000000001").unwrap();
    let system_signer_address =
        Address::from_str("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead").unwrap();

    let da_service = MockDaService::new(MockAddress::default());

    // start rollup on da block 3
    for _ in 0..3 {
        da_service.publish_test_block().await.unwrap();
    }

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task =
        tokio::spawn(async move {
            start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests-low-block-gas-limit"),
            BasicKernelGenesisPaths {
                chain_state:
                    "../test-data/genesis/integration-tests-low-block-gas-limit/chain_state.json"
                        .into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            4,
            true,
            None,
            // Increase max account slots to not stuck as spammer
            Some(SequencerConfig {
                min_soft_confirmations_per_commitment: 1000,
                mempool_conf: SequencerMempoolConfig {max_account_slots: 100, ..Default::default() }
            })
        )
        .await;
        });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;
    // sys tx use 45756 + 75710 = 121466gas
    // the block gas limit is 1_000_000 because the system txs gas limit is 1_000_000

    // 1000000 - 121466 = 878534 gas is left in block
    // 878534 / 21000 = 41,8 so 41 ether transfer transactions can be included in the block

    // send 41 ether transfer transactions
    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    for _ in 0..40 {
        seq_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await
            .unwrap();
    }

    // 41st tx should be the last tx in the soft batch
    let last_in_tx = seq_test_client
        .send_eth(addr, None, None, None, 0u128)
        .await;

    // this tx should not be in soft batch
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

    let las_tx_hash = last_in_receipt.transaction_hash;
    let last_tx_raw = seq_test_client
        .eth_get_transaction_by_hash(las_tx_hash, Some(false))
        .await
        .unwrap()
        .rlp();

    assert!(last_in_receipt.block_number.is_some());

    // last in tx byte array should be a sub array of txs[0]
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

    // not in tx byte array should not be a sub array of txs[0]
    assert!(find_subarray(
        initial_soft_batch.txs.unwrap()[0].tx.as_slice(),
        &not_in_raw
    )
    .is_none());

    // assert!(not_in_receipt.block_number.is_none());

    // now on another block with system txs call ether transfers 42 times and see that the softbatch txs are the same

    seq_test_client.send_publish_batch_request().await;

    Ok(())
}

fn find_subarray(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/*

Some([HexTx { tx: [184, 94, 89, 158, 176, 202, 24, 181, 222, 56, 113, 151, 91, 81, 175, 218, 41, 152, 1, 103, 65, 54, 139, 168, 88, 189, 136, 138, 37, 91, 255, 96, 219, 197, 222, 209, 63, 128, 60, 62, 84, 197, 9, 76, 77, 2, 190, 195, 105, 45, 195, 114, 245, 252, 144, 118, 80, 70, 136, 73, 232, 179, 9, 13, 32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124, 137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33, 116, 0, 0, 0, 1, 1, 0, 0, 0, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 128, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 81, 84, 144, 153, 250, 6, 243, 39, 253, 40, 20, 176, 99, 99, 173, 150, 64, 149, 164, 199, 121, 178, 164, 165, 144, 27, 219, 231, 195, 14, 217, 218, 160, 117, 218, 12, 116, 0, 64, 187, 61, 73, 109, 77, 231, 176, 120, 169, 184, 12, 27, 183, 126, 32, 44, 21, 6, 224, 93, 250, 244, 107, 196, 232, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }])
Some([HexTx { tx: [93, 215, 208, 75, 5, 17, 113, 90, 133, 245, 180, 203, 97, 148, 104, 155, 5, 123, 154, 123, 240, 239, 223, 11, 52, 250, 105, 201, 255, 229, 30, 118, 50, 49, 182, 219, 192, 203, 119, 228, 107, 25, 31, 235, 67, 125, 33, 76, 27, 239, 14, 80, 200, 37, 166, 42, 15, 87, 34, 145, 210, 194, 99, 0, 32, 64, 64, 227, 100, 193, 15, 43, 236, 156, 31, 229, 0, 161, 205, 76, 36, 124, 137, 214, 80, 160, 30, 215, 232, 44, 171, 168, 103, 135, 124, 33, 91, 4, 0, 0, 1, 10, 0, 0, 0, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 128, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 81, 84, 144, 153, 250, 6, 243, 39, 253, 40, 20, 176, 99, 99, 173, 150, 64, 149, 164, 199, 121, 178, 164, 165, 144, 27, 219, 231, 195, 14, 217, 218, 160, 117, 218, 12, 116, 0, 64, 187, 61, 73, 109, 77, 231, 176, 120, 169, 184, 12, 27, 183, 126, 32, 44, 21, 6, 224, 93, 250, 244, 107, 196, 232, 165, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 1, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 190, 203, 136, 28, 95, 179, 230, 159, 170, 86, 7, 180, 32, 17, 188, 216, 170, 188, 81, 156, 106, 254, 131, 170, 246, 62, 154, 48, 225, 76, 113, 9, 160, 62, 37, 59, 72, 24, 135, 228, 150, 121, 124, 184, 129, 215, 142, 137, 198, 231, 135, 53, 123, 207, 74, 44, 24, 144, 94, 233, 221, 90, 14, 55, 55, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 2, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 208, 183, 182, 8, 85, 182, 70, 11, 210, 143, 95, 70, 48, 85, 154, 44, 81, 158, 69, 191, 183, 235, 229, 214, 150, 131, 37, 20, 97, 92, 91, 119, 160, 105, 90, 91, 41, 148, 218, 13, 101, 213, 36, 107, 136, 232, 180, 62, 191, 43, 239, 123, 62, 112, 175, 196, 112, 14, 210, 179, 42, 161, 217, 215, 17, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 3, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 190, 204, 251, 0, 51, 173, 175, 225, 32, 251, 139, 64, 252, 76, 217, 198, 131, 105, 101, 231, 73, 170, 79, 250, 200, 73, 187, 174, 15, 125, 82, 79, 160, 78, 16, 236, 65, 13, 145, 91, 158, 5, 228, 11, 134, 53, 6, 195, 40, 77, 111, 200, 184, 53, 32, 194, 243, 125, 188, 185, 167, 181, 89, 196, 247, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 4, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 128, 160, 171, 178, 56, 63, 169, 49, 159, 199, 48, 68, 14, 28, 244, 47, 234, 69, 88, 33, 235, 126, 239, 133, 190, 119, 30, 114, 59, 157, 63, 92, 27, 200, 160, 100, 219, 67, 109, 251, 142, 20, 63, 187, 14, 117, 40, 190, 185, 238, 198, 73, 107, 167, 209, 124, 156, 216, 97, 231, 228, 45, 195, 55, 104, 84, 57, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 5, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 116, 174, 163, 209, 93, 68, 66, 150, 216, 181, 9, 16, 226, 199, 120, 204, 240, 216, 201, 173, 142, 171, 20, 39, 234, 199, 211, 224, 199, 236, 203, 76, 160, 2, 216, 220, 73, 139, 197, 96, 108, 17, 168, 214, 229, 49, 28, 28, 201, 140, 96, 142, 98, 68, 230, 90, 7, 178, 244, 146, 185, 246, 15, 37, 117, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 6, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 128, 160, 189, 89, 90, 152, 221, 228, 25, 227, 193, 159, 9, 48, 70, 177, 121, 79, 219, 227, 158, 33, 244, 154, 126, 226, 21, 67, 248, 149, 232, 226, 196, 79, 160, 76, 214, 227, 51, 149, 79, 65, 73, 193, 37, 117, 22, 150, 211, 169, 249, 100, 80, 247, 77, 51, 58, 87, 223, 139, 76, 185, 113, 174, 228, 126, 105, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 7, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 72, 3, 213, 228, 99, 94, 239, 51, 106, 134, 25, 22, 42, 46, 44, 232, 146, 239, 163, 216, 245, 94, 142, 79, 51, 14, 102, 66, 150, 39, 248, 246, 160, 84, 188, 86, 142, 3, 40, 108, 20, 162, 201, 69, 89, 46, 12, 106, 147, 101, 105, 88, 23, 255, 21, 150, 39, 150, 126, 163, 58, 97, 95, 149, 236, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 8, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 1, 160, 13, 63, 42, 63, 162, 242, 41, 59, 254, 208, 240, 69, 144, 77, 78, 76, 234, 4, 179, 4, 7, 144, 0, 88, 149, 253, 112, 25, 31, 199, 118, 5, 160, 117, 107, 137, 46, 124, 220, 241, 121, 155, 243, 184, 247, 232, 63, 1, 97, 240, 221, 246, 219, 35, 202, 109, 212, 154, 189, 102, 72, 175, 47, 10, 43, 107, 0, 0, 0, 2, 248, 104, 130, 22, 23, 9, 10, 132, 59, 154, 202, 1, 130, 82, 8, 148, 243, 159, 214, 229, 26, 173, 136, 246, 244, 206, 106, 184, 130, 114, 121, 207, 255, 185, 34, 102, 128, 128, 192, 128, 160, 208, 34, 126, 219, 20, 65, 55, 58, 178, 56, 238, 176, 127, 229, 49, 229, 134, 234, 125, 77, 137, 189, 131, 96, 218, 99, 252, 78, 128, 239, 197, 22, 160, 26, 119, 127, 155, 66, 64, 118, 126, 7, 99, 131, 143, 32, 83, 173, 2, 130, 139, 80, 239, 98, 78, 169, 109, 206, 79, 74, 157, 151, 104, 129, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }]

*/
