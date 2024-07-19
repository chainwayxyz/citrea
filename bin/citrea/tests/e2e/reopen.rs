/// Tests for closing down and reopening nodes with the same data
/// to make sure the nodes can continue from where they left off
/// In the past we had problems with this scenario.
use std::str::FromStr;
use std::time::Duration;

use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag};
use sov_mock_da::{MockAddress, MockDaService};
use sov_stf_runner::ProverConfig;
use tokio::runtime::Runtime;
use tokio::time::sleep;

use crate::e2e::copy_dir_recursive;
use crate::evm::{init_test_rollup, make_test_client};
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block,
    wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_reopen_full_node() -> Result<(), anyhow::Error> {
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

#[tokio::test(flavor = "multi_thread")]
async fn test_reopen_prover() -> Result<(), anyhow::Error> {
    // citrea::initialize_logging(tracing::Level::DEBUG);

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
    let (thread_kill_sender, thread_kill_receiver) = std::sync::mpsc::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_db_dir_cloned = prover_db_dir.clone();

    let _handle = std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let _prover_node_task = tokio::spawn(async move {
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
        });
        thread_kill_receiver.recv().unwrap();
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();
    let prover_node_test_client = make_test_client(prover_node_port).await;

    // prover should not have any blocks saved
    assert_eq!(prover_node_test_client.eth_block_number().await, 0);
    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        seq_test_client.send_publish_batch_request().await;
    }
    wait_for_l2_block(&seq_test_client, 3, None).await;

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

    // prover_node_task.abort();
    thread_kill_sender.send("kill").unwrap();

    sleep(Duration::from_secs(1)).await;

    let _ = copy_dir_recursive(&prover_db_dir, &storage_dir.path().join("prover_copy"));
    sleep(Duration::from_secs(1)).await;

    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();
    let (thread_kill_sender, thread_kill_receiver) = std::sync::mpsc::channel();

    let prover_copy_db_dir = storage_dir.path().join("prover_copy");
    let da_db_dir_cloned = da_db_dir.clone();

    let _handle = std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let _prover_node_task = tokio::spawn(async move {
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
        });

        thread_kill_receiver.recv().unwrap();
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();
    let prover_node_test_client = make_test_client(prover_node_port).await;

    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 6, None).await;
    // Still should have 4 blocks there are no commitments yet
    wait_for_l2_block(&prover_node_test_client, 6, None).await;
    // Allow for the L2 block to be commited and stored
    // Otherwise, the L2 block height might be registered but it hasn't
    // been processed inside the EVM yet.
    sleep(Duration::from_secs(1)).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 6);

    thread_kill_sender.send("kill").unwrap();
    sleep(Duration::from_secs(2)).await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 8, None).await;
    let _ = copy_dir_recursive(&prover_db_dir, &storage_dir.path().join("prover_copy2"));

    sleep(Duration::from_secs(2)).await;
    // Reopen prover with the new path
    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();
    let (thread_kill_sender, thread_kill_receiver) = std::sync::mpsc::channel();
    let prover_copy2_dir_cloned = storage_dir.path().join("prover_copy2");
    let da_db_dir_cloned = da_db_dir.clone();

    let _handle = std::thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let _prover_node_task = tokio::spawn(async move {
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
        });

        thread_kill_receiver.recv().unwrap();
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();
    let prover_node_test_client = make_test_client(prover_node_port).await;
    sleep(Duration::from_secs(2)).await;
    // Publish a DA to force prover to process new blocks
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 6, None).await;

    // We have 8 blocks in total, make sure the prover syncs
    // and starts proving the second commitment.
    wait_for_l2_block(&prover_node_test_client, 8, Some(Duration::from_secs(300))).await;
    assert_eq!(prover_node_test_client.eth_block_number().await, 8);
    sleep(Duration::from_secs(1)).await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 9, None).await;
    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 7, None).await;
    sleep(Duration::from_secs(1)).await;
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
    thread_kill_sender.send("kill").unwrap();
    Ok(())
}
