use std::path::PathBuf;
use std::str::FromStr;

use alloy::signers::wallet::LocalWallet;
use alloy::signers::Signer;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag};
use tokio::task::JoinHandle;

use crate::evm::make_test_client;
use crate::test_client::{TestClient, MAX_FEE_PER_GAS};
use crate::test_helpers::{start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    TEST_DATA_GENESIS_PATH,
};

async fn initialize_test(
    sequencer_path: PathBuf,
    db_path: PathBuf,
) -> (JoinHandle<()>, Box<TestClient>) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_path,
            db_path,
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
    let test_client = make_test_client(seq_port).await;

    (seq_task, test_client)
}

/// Transaction with equal nonce to last tx should not be accepted by mempool.
#[tokio::test(flavor = "multi_thread")]
async fn test_same_nonce_tx_should_panic() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    let _pending = test_client
        .send_eth(addr, None, None, Some(0), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1
    let _pending = test_client
        .send_eth(addr, None, None, Some(1), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1 again and expect it to be rejected
    let res = test_client.send_eth(addr, None, None, Some(1), 0u128).await;

    assert!(res.unwrap_err().to_string().contains("already known"));

    seq_task.abort();
}

///  Transaction with nonce lower than account's nonce on state should not be accepted by mempool.
#[tokio::test(flavor = "multi_thread")]
async fn test_nonce_too_low() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    let _pending = test_client
        .send_eth(addr, None, None, Some(0), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1
    let _pending = test_client
        .send_eth(addr, None, None, Some(1), 0u128)
        .await
        .unwrap();

    let res = test_client.send_eth(addr, None, None, Some(0), 0u128).await;
    assert!(res.unwrap_err().to_string().contains("already known"));

    seq_task.abort();
}

/// Transaction with nonce higher than account's nonce should be accepted by the mempool
/// but shouldn't be received by the sequencer (so it doesn't end up in the block)
#[tokio::test(flavor = "multi_thread")]
async fn test_nonce_too_high() {
    // citrea::initialize_logging(tracing::Level::INFO);

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    let _tx_hash = test_client
        .send_eth(addr, None, None, Some(0), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1
    let _tx_hash1 = test_client
        .send_eth(addr, None, None, Some(1), 0u128)
        .await
        .unwrap();
    // send tx with nonce 0 expect it to be rejected
    let tx_hash2 = test_client
        .send_eth(addr, None, None, Some(3), 0u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    // assert the block does not contain the tx with nonce too high
    let block_transactions = block.transactions.as_hashes().unwrap();
    assert!(!block_transactions.contains(tx_hash2.tx_hash()));
    seq_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_order_by_fee() {
    // citrea::initialize_logging();

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(Some(chain_id));
    let poor_addr = key.address();

    let poor_test_client = TestClient::new(chain_id, key, poor_addr, test_client.rpc_addr).await;

    let _addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let sent_tx_hash1 = test_client
        .send_eth(poor_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions = block.transactions.as_hashes().unwrap();
    assert!(block_transactions.contains(sent_tx_hash1.tx_hash()));

    // now make some txs  from different accounts with different fees and see which tx lands first in block
    let tx_hash_poor = poor_test_client
        .send_eth(
            test_client.from_addr,
            Some(100),
            Some(MAX_FEE_PER_GAS),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    let tx_hash_rich = test_client
        .send_eth(
            poor_test_client.from_addr,
            Some(1000),
            Some(MAX_FEE_PER_GAS),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // the rich tx should be in the block before the poor tx
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions = block.transactions.as_hashes().unwrap();
    assert!(block_transactions[0] == *tx_hash_rich.tx_hash());
    assert!(block_transactions[1] == *tx_hash_poor.tx_hash());

    // now change the order the txs are sent, the assertions should be the same
    let tx_hash_rich = test_client
        .send_eth(
            poor_test_client.from_addr,
            Some(1000),
            Some(1000000000001),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    // now make some txs  from different accounts with different fees and see which tx lands first in block
    let tx_hash_poor = poor_test_client
        .send_eth(
            test_client.from_addr,
            Some(100),
            Some(100000000001),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 3, None).await;

    // the rich tx should be in the block before the poor tx
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    // first index tx should be rich tx
    let block_transactions = block.transactions.as_hashes().unwrap();
    assert!(block_transactions[0] == *tx_hash_rich.tx_hash());
    assert!(block_transactions[1] == *tx_hash_poor.tx_hash());

    seq_task.abort();
}

/// Send a transaction that pays less base fee then required.
/// Publish block, tx should not be in block but should still be in the mempool.
#[tokio::test(flavor = "multi_thread")]
async fn test_tx_with_low_base_fee() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(Some(chain_id));
    let poor_addr = key.address();

    let _pending = test_client
        .send_eth(poor_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let tx_hash_low_fee = test_client
        .send_eth(
            poor_addr,
            Some(1),
            // normally base fee is 875 000 000
            Some(1_000_001),
            None,
            5_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions: Vec<_> = block.transactions.hashes().copied().collect();
    assert!(!block_transactions.contains(tx_hash_low_fee.tx_hash()));

    // TODO: also check if tx is in the mempool after https://github.com/chainwayxyz/citrea/issues/83

    seq_task.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_same_nonce_tx_replacement() {
    // citrea::initialize_logging();

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let tx_hash = test_client
        .send_eth(addr, Some(100), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap();

    // Replacement error with lower fee
    let err = test_client
        .send_eth(addr, Some(90), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement error with equal fee
    let err = test_client
        .send_eth(addr, Some(100), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("already known"));

    // Replacement error with enough base fee but low priority fee
    let err = test_client
        .send_eth(addr, Some(10), Some(MAX_FEE_PER_GAS + 100), Some(0), 0u128)
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement error with enough base fee but low priority fee
    let err = test_client
        .send_eth(
            addr,
            Some(10),
            Some(MAX_FEE_PER_GAS + 100000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement error with not enough fee increase (like 5% or sth.)
    let err = test_client
        .send_eth(
            addr,
            Some(105),
            Some(MAX_FEE_PER_GAS + 1000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement success with 10% fee bump - does not work
    let err = test_client
        .send_eth(
            addr,
            Some(110), // 10% increase
            Some(MAX_FEE_PER_GAS + 1000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    let err = test_client
        .send_eth(
            addr,
            Some(111),                         // 11% increase
            Some(MAX_FEE_PER_GAS + 100000000), // Not increasing more than 10 percent - should fail.
            Some(0),
            0u128,
        )
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement success with more than 10% bump
    let tx_hash_11_bump = test_client
        .send_eth(
            addr,
            Some(111),                          // 11% increase
            Some(MAX_FEE_PER_GAS + 1000000000), // More than 10 percent - should succeed.
            Some(0),
            0u128,
        )
        .await
        .unwrap();

    assert_ne!(tx_hash.tx_hash(), tx_hash_11_bump.tx_hash());

    // Replacement success with more than 10% bump
    let tx_hash_25_bump = test_client
        .send_eth(
            addr,
            Some(125),
            Some(MAX_FEE_PER_GAS + 100000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap();

    assert_ne!(tx_hash_11_bump.tx_hash(), tx_hash_25_bump.tx_hash());

    let tx_hash_ultra_bump = test_client
        .send_eth(
            addr,
            Some(1000),
            Some(MAX_FEE_PER_GAS + 10000000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap();

    assert_ne!(tx_hash_25_bump.tx_hash(), tx_hash_ultra_bump.tx_hash());

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let block_transactions = block.transactions.as_hashes().unwrap();
    assert!(!block_transactions.contains(tx_hash.tx_hash()));
    assert!(!block_transactions.contains(tx_hash_11_bump.tx_hash()));
    assert!(!block_transactions.contains(tx_hash_25_bump.tx_hash()));
    assert!(block_transactions.contains(tx_hash_ultra_bump.tx_hash()));

    seq_task.abort();
}
