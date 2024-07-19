use std::str::FromStr;

use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag, TxHash};

use crate::e2e::{initialize_test, TestConfig};
use crate::evm::init_test_rollup;
use crate::test_helpers::{start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};
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
