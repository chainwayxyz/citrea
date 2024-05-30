use std::path::PathBuf;
use std::str::FromStr;

use citrea_sequencer::{SequencerConfig, SequencerMempoolConfig};
use citrea_stf::genesis_config::GenesisPaths;
use ethers::abi::Address;
use ethers_signers::{LocalWallet, Signer};
use reth_primitives::BlockNumberOrTag;
use rollup_constants::TEST_PRIVATE_KEY;
use tokio::task::JoinHandle;

use crate::evm::make_test_client;
use crate::test_client::{TestClient, MAX_FEE_PER_GAS};
use crate::test_helpers::{start_rollup, tempdir_with_children, NodeMode};
use crate::{DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT};

async fn initialize_test(
    sequencer_path: PathBuf,
    db_path: PathBuf,
) -> (JoinHandle<()>, Box<TestClient>) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
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
#[tokio::test]
async fn test_same_nonce_tx_should_panic() {
    // citrea::initialize_logging();

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    test_client
        .send_eth(addr, None, None, Some(0), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1
    test_client
        .send_eth(addr, None, None, Some(1), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1 again and expect it to be rejected
    let res = test_client.send_eth(addr, None, None, Some(1), 0u128).await;

    assert!(res.unwrap_err().to_string().contains("already known"));

    seq_task.abort();
}

///  Transaction with nonce lower than account's nonce on state should not be accepted by mempool.
#[tokio::test]
async fn test_nonce_too_low() {
    // citrea::initialize_logging();

    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // send tx with nonce 0
    test_client
        .send_eth(addr, None, None, Some(0), 0u128)
        .await
        .unwrap();
    // send tx with nonce 1
    test_client
        .send_eth(addr, None, None, Some(1), 0u128)
        .await
        .unwrap();

    let res = test_client.send_eth(addr, None, None, Some(0), 0u128).await;
    assert!(res.unwrap_err().to_string().contains("already known"));

    seq_task.abort();
}

/// Transaction with nonce higher than account's nonce should be accepted by the mempool
/// but shouldn't be received by the sequencer (so it doesn't end up in the block)
#[tokio::test]
async fn test_nonce_too_high() {
    // citrea::initialize_logging();

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
    assert!(!block.transactions.contains(&tx_hash2.tx_hash()));
    seq_task.abort();
}

#[tokio::test]
async fn test_order_by_fee() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);
    let poor_addr = key.address();

    let poor_test_client = TestClient::new(chain_id, key, poor_addr, test_client.rpc_addr).await;

    let _addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let sent_tx_hash1 = test_client
        .send_eth(poor_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(block.transactions.contains(&sent_tx_hash1.tx_hash()));

    // now make some txs  from different accounts with different fees and see which tx lands first in block
    let tx_hash_poor = poor_test_client
        .send_eth(
            test_client.from_addr,
            Some(100u64),
            Some(MAX_FEE_PER_GAS),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    let tx_hash_rich = test_client
        .send_eth(
            poor_test_client.from_addr,
            Some(1000u64),
            Some(MAX_FEE_PER_GAS),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    // the rich tx should be in the block before the poor tx
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(block.transactions[0] == tx_hash_rich.tx_hash());
    assert!(block.transactions[1] == tx_hash_poor.tx_hash());

    // now change the order the txs are sent, the assertions should be the same
    let tx_hash_rich = test_client
        .send_eth(
            poor_test_client.from_addr,
            Some(1000u64),
            Some(1000000000001u64),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    // now make some txs  from different accounts with different fees and see which tx lands first in block
    let tx_hash_poor = poor_test_client
        .send_eth(
            test_client.from_addr,
            Some(100u64),
            Some(100000000001u64),
            None,
            2_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    // the rich tx should be in the block before the poor tx
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    // first index tx should be rich tx
    assert!(block.transactions[0] == tx_hash_rich.tx_hash());
    assert!(block.transactions[1] == tx_hash_poor.tx_hash());

    seq_task.abort();
}

/// Send a transaction that pays less base fee then required.
/// Publish block, tx should not be in block but should still be in the mempool.
#[tokio::test]
async fn test_tx_with_low_base_fee() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(chain_id);
    let poor_addr = key.address();

    test_client
        .send_eth(poor_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let tx_hash_low_fee = test_client
        .send_eth(
            poor_addr,
            Some(1u64),
            // normally base fee is 875 000 000
            Some(1_000_001u64),
            None,
            5_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(!block.transactions.contains(&tx_hash_low_fee.tx_hash()));

    // TODO: also check if tx is in the mempool after https://github.com/chainwayxyz/citrea/issues/83

    seq_task.abort();
}

#[tokio::test]
async fn test_same_nonce_tx_replacement() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let tx_hash = test_client
        .send_eth(addr, Some(100u64), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap();

    // Replacement error with lower fee
    let err = test_client
        .send_eth(addr, Some(90u64), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement error with equal fee
    let err = test_client
        .send_eth(addr, Some(100u64), Some(MAX_FEE_PER_GAS), Some(0), 0u128)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("already known"));

    // Replacement error with enough base fee but low priority fee
    let err = test_client
        .send_eth(
            addr,
            Some(10u64),
            Some(MAX_FEE_PER_GAS + 100u64),
            Some(0),
            0u128,
        )
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .contains("replacement transaction underpriced"));

    // Replacement error with enough base fee but low priority fee
    let err = test_client
        .send_eth(
            addr,
            Some(10u64),
            Some(MAX_FEE_PER_GAS + 100000000000u64),
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
            Some(105u64),
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
            Some(110u64), // 10% increase
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
            Some(111u64),                      // 11% increase
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
            Some(111u64),                       // 11% increase
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
            Some(125u64),
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
            Some(1000u64),
            Some(MAX_FEE_PER_GAS + 10000000000000),
            Some(0),
            0u128,
        )
        .await
        .unwrap();

    assert_ne!(tx_hash_25_bump.tx_hash(), tx_hash_ultra_bump.tx_hash());

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    assert!(!block.transactions.contains(&tx_hash.tx_hash()));
    assert!(!block.transactions.contains(&tx_hash_11_bump.tx_hash()));
    assert!(!block.transactions.contains(&tx_hash_25_bump.tx_hash()));
    assert!(block.transactions.contains(&tx_hash_ultra_bump.tx_hash()));

    seq_task.abort();
}

/// Transactions with a high gas limit should be accounted for by using
/// their actual cumulative gas consumption to prevent them from reserving
/// whole blocks on their own.
#[tokio::test]
async fn test_gas_limit_too_high() {
    // citrea::initialize_logging();

    let db_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let target_gas_limit: u64 = 15_000_000;
    let transfer_gas_limit = 21_000;
    let system_txs_gas_used = 415_811;
    let tx_count = (target_gas_limit - system_txs_gas_used).div_ceil(transfer_gas_limit);

    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir,
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
                    // Set the max number of txs per user account
                    // to be higher than the number of transactions
                    // we want to send.
                    max_account_slots: tx_count * 2,
                    ..Default::default()
                },
                db_config: Default::default(),
            }),
            Some(true),
            100,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    let mut tx_hashes = vec![];
    // Loop until tx_count (inclusive).
    // This means that we are going to have 5 transactions which have not bee included.
    for _ in 0..=tx_count + 4 {
        let tx_hash = test_client
            .send_eth_with_gas(addr, None, None, 10_000_000, 0u128)
            .await
            .unwrap();
        tx_hashes.push(tx_hash);
    }

    test_client.send_publish_batch_request().await;

    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    // assert the block contains all txs apart from the last 5
    for tx_hash in tx_hashes[0..tx_hashes.len() - 5].iter() {
        assert!(block.transactions.contains(&tx_hash.tx_hash()));
    }
    for tx_hash in tx_hashes[tx_hashes.len() - 5..].iter() {
        assert!(!block.transactions.contains(&tx_hash.tx_hash()));
    }
    seq_task.abort();
}
