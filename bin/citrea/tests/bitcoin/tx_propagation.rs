use std::net::SocketAddr;
use std::str::FromStr;

use alloy::network::TransactionResponse;
use alloy_primitives::{Address, TxHash, B256, U64};
use alloy_rpc_types::BlockNumberOrTag;
use async_trait::async_trait;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;

use super::get_citrea_path;
use crate::common::make_test_client;

/// Full node receives transaction from RPC.
/// Sends it to the sequencer.
/// Wait for the sequencer to publish a block.
/// We check if the tx is included in the block.
struct FullNodeSendTxTest;

#[async_trait]
impl TestCase for FullNodeSendTxTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;
        let full_node_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265")?;

        let tx_hash = full_node_test_client
            .send_eth(addr, None, None, None, 0u128)
            .await?;

        sequencer.client.send_publish_batch_request().await?;

        sequencer.wait_for_l2_height(1, None).await?;
        full_node.wait_for_l2_height(1, None).await?;

        let seq_block = seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        let full_node_block = full_node_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;

        let seq_transactions = seq_block.transactions.as_hashes().unwrap();
        let full_node_transactions = full_node_block.transactions.as_hashes().unwrap();
        assert!(seq_transactions.contains(tx_hash.tx_hash()));
        assert!(full_node_transactions.contains(tx_hash.tx_hash()));
        assert_eq!(
            seq_block.header.state_root,
            full_node_block.header.state_root
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_full_node_send_tx() -> Result<()> {
    TestCaseRunner::new(FullNodeSendTxTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Full node receives transaction from RPC.
/// Sends it to the sequencer.
/// We send eth_getTransactionByHash RPC to the full node.
/// The full node checks state then asks to sequencer, then returns the result.
/// We check if the tx is included in the response.
struct GetTransactionByHashTest;

#[async_trait]
impl TestCase for GetTransactionByHashTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        let full_node_test_client = make_test_client(SocketAddr::new(
            full_node.config().rpc_bind_host().parse()?,
            full_node.config().rpc_bind_port(),
        ))
        .await?;

        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265")?;

        // Create test transactions
        let pending_tx1 = seq_test_client
            .send_eth(addr, None, None, None, 1_000_000_000u128)
            .await?;

        let pending_tx2 = seq_test_client
            .send_eth(addr, None, None, None, 1_000_000_000u128)
            .await?;

        // Currently there are two txs in the pool, the full node should be able to get them
        // Should get with mempool_only true
        let tx1 = full_node_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        // Should get with mempool_only false/none
        let tx2 = full_node_test_client
            .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;

        assert!(tx1.is_some());
        assert!(tx2.is_some());
        let tx1 = tx1.unwrap();
        let tx2 = tx2.unwrap();
        assert!(tx1.block_hash.is_none());
        assert!(tx2.block_hash.is_none());
        assert_eq!(tx1.tx_hash(), *pending_tx1.tx_hash());
        assert_eq!(tx2.tx_hash(), *pending_tx2.tx_hash());

        // Sequencer should also be able to get them
        // Should get just by checking the pool
        let tx1 = seq_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        let tx2 = seq_test_client
            .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;

        assert!(tx1.is_some());
        assert!(tx2.is_some());
        let tx1 = tx1.unwrap();
        let tx2 = tx2.unwrap();
        assert!(tx1.block_hash.is_none());
        assert!(tx2.block_hash.is_none());
        assert_eq!(tx1.tx_hash(), *pending_tx1.tx_hash());
        assert_eq!(tx2.tx_hash(), *pending_tx2.tx_hash());

        // Include transactions in a block
        sequencer.client.send_publish_batch_request().await?;
        full_node.wait_for_l2_height(1, None).await?;

        // Make sure txs are in the block
        let seq_block = seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        let seq_block_transactions = seq_block.transactions.as_hashes().unwrap();
        assert!(seq_block_transactions.contains(pending_tx1.tx_hash()));
        assert!(seq_block_transactions.contains(pending_tx2.tx_hash()));

        // Same operations after the block is published, both sequencer and full node should be able to get them.
        // Should not get with mempool_only true because it checks the sequencer mempool only
        let non_existent_tx = full_node_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        // This should be none because it is not in the mempool anymore
        assert!(non_existent_tx.is_none());

        let tx1 = full_node_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
            .await;
        let tx2 = full_node_test_client
            .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;

        assert!(tx1.is_some());
        assert!(tx2.is_some());
        let tx1 = tx1.unwrap();
        let tx2 = tx2.unwrap();
        assert!(tx1.block_hash.is_some());
        assert!(tx2.block_hash.is_some());

        // Should not get with mempool_only true because it checks mempool only
        let none_existent_tx = seq_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        // This should be none because it is not in the mempool anymore
        assert!(none_existent_tx.is_none());

        // In other cases should check the block and find the tx
        let tx1 = seq_test_client
            .eth_get_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
            .await;
        let tx2 = seq_test_client
            .eth_get_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;

        assert!(tx1.is_some());
        assert!(tx2.is_some());
        let tx1 = tx1.unwrap();
        let tx2 = tx2.unwrap();
        assert!(tx1.block_hash.is_some());
        assert!(tx2.block_hash.is_some());

        // Create random tx hash and make sure it returns None
        let random_tx_hash = TxHash::random();
        assert!(seq_test_client
            .eth_get_transaction_by_hash(random_tx_hash, None)
            .await
            .is_none());
        assert!(full_node_test_client
            .eth_get_transaction_by_hash(random_tx_hash, None)
            .await
            .is_none());

        Ok(())
    }
}

#[tokio::test]
async fn test_get_transaction_by_hash() -> Result<()> {
    TestCaseRunner::new(GetTransactionByHashTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Tests eth_getRawTransactionByHash, eth_getRawTransactionByBlockHashAndIndex,
/// and eth_getRawTransactionByBlockNumberAndIndex RPCs.
/// Verifies raw bytes hash to the correct transaction hash.
/// Tests mempool (pending) and confirmed (in-block) scenarios.
struct GetRawTransactionTest;

#[async_trait]
impl TestCase for GetRawTransactionTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        let full_node_test_client = make_test_client(SocketAddr::new(
            full_node.config().rpc_bind_host().parse()?,
            full_node.config().rpc_bind_port(),
        ))
        .await?;

        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265")?;

        // Send two transactions
        let pending_tx1 = seq_test_client
            .send_eth(addr, None, None, None, 1_000_000_000u128)
            .await?;

        let pending_tx2 = seq_test_client
            .send_eth(addr, None, None, None, 2_000_000_000u128)
            .await?;

        // === Pending stage: test getRawTransactionByHash on both full node and sequencer ===

        // Full node: mempool_only=true
        let raw_tx1_mempool_fn = full_node_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        assert!(raw_tx1_mempool_fn.is_some(), "Full node should find pending tx in mempool");
        assert_eq!(
            alloy::primitives::keccak256(raw_tx1_mempool_fn.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        // Sequencer: mempool_only=true
        let raw_tx1_mempool_seq = seq_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
            .await;
        assert!(raw_tx1_mempool_seq.is_some(), "Sequencer should find pending tx in mempool");
        assert_eq!(
            alloy::primitives::keccak256(raw_tx1_mempool_seq.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        // Sequencer and full node should return same raw bytes
        assert_eq!(
            raw_tx1_mempool_fn.as_ref().unwrap(),
            raw_tx1_mempool_seq.as_ref().unwrap(),
            "Sequencer and full node should return identical raw bytes for pending tx"
        );

        // Full node: mempool_only=None (should also find via sequencer fallback)
        let raw_tx2_fn = full_node_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;
        assert!(raw_tx2_fn.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_tx2_fn.as_ref().unwrap()),
            *pending_tx2.tx_hash(),
        );

        // Sequencer: mempool_only=None
        let raw_tx2_seq = seq_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;
        assert!(raw_tx2_seq.is_some());
        assert_eq!(raw_tx2_fn.unwrap(), raw_tx2_seq.unwrap());

        // Block-based raw tx methods should return None when no txs in block
        let raw_by_number_pending = full_node_test_client
            .eth_get_raw_tx_by_block_number_and_index(BlockNumberOrTag::Latest, U64::from(0))
            .await;
        assert!(raw_by_number_pending.is_none());

        // === Include transactions in a block ===
        sequencer.client.send_publish_batch_request().await?;
        full_node.wait_for_l2_height(1, None).await?;

        // After block publication, mempool_only=true should return None on both
        assert!(
            full_node_test_client
                .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
                .await
                .is_none(),
            "Full node should not find confirmed tx in mempool"
        );
        assert!(
            seq_test_client
                .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(true))
                .await
                .is_none(),
            "Sequencer should not find confirmed tx in mempool"
        );

        // === Confirmed stage: getRawTransactionByHash on both nodes ===
        let raw_tx1_confirmed_fn = full_node_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
            .await;
        assert!(raw_tx1_confirmed_fn.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_tx1_confirmed_fn.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        let raw_tx1_confirmed_seq = seq_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx1.tx_hash(), Some(false))
            .await;
        assert!(raw_tx1_confirmed_seq.is_some());
        assert_eq!(
            raw_tx1_confirmed_fn.as_ref().unwrap(),
            raw_tx1_confirmed_seq.as_ref().unwrap(),
            "Sequencer and full node should return identical raw bytes for confirmed tx"
        );

        let raw_tx2_confirmed_fn = full_node_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;
        assert!(raw_tx2_confirmed_fn.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_tx2_confirmed_fn.as_ref().unwrap()),
            *pending_tx2.tx_hash(),
        );

        let raw_tx2_confirmed_seq = seq_test_client
            .eth_get_raw_transaction_by_hash(*pending_tx2.tx_hash(), None)
            .await;
        assert!(raw_tx2_confirmed_seq.is_some());
        assert_eq!(raw_tx2_confirmed_fn.unwrap(), raw_tx2_confirmed_seq.unwrap());

        // === Block-based queries (same EVM code path on both nodes, only test on full node) ===
        let block = full_node_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(1)))
            .await;
        let block_txs = block.transactions.as_hashes().unwrap();
        assert!(block_txs.contains(pending_tx1.tx_hash()));
        assert!(block_txs.contains(pending_tx2.tx_hash()));

        let tx1_index = block_txs
            .iter()
            .position(|h| h == pending_tx1.tx_hash())
            .unwrap();

        // getRawTransactionByBlockHashAndIndex
        let raw_by_block_hash = full_node_test_client
            .eth_get_raw_tx_by_block_hash_and_index(block.header.hash, U64::from(tx1_index as u64))
            .await;
        assert!(raw_by_block_hash.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_by_block_hash.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        // getRawTransactionByBlockNumberAndIndex
        let raw_by_block_number = full_node_test_client
            .eth_get_raw_tx_by_block_number_and_index(
                BlockNumberOrTag::Number(1),
                U64::from(tx1_index as u64),
            )
            .await;
        assert!(raw_by_block_number.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_by_block_number.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        // getRawTransactionByBlockNumberAndIndex with Latest tag
        let raw_by_latest = full_node_test_client
            .eth_get_raw_tx_by_block_number_and_index(
                BlockNumberOrTag::Latest,
                U64::from(tx1_index as u64),
            )
            .await;
        assert!(raw_by_latest.is_some());
        assert_eq!(
            alloy::primitives::keccak256(raw_by_latest.as_ref().unwrap()),
            *pending_tx1.tx_hash(),
        );

        // All methods should return identical bytes for the same tx
        assert_eq!(
            raw_by_block_hash.unwrap(),
            raw_by_block_number.unwrap(),
            "Block hash and block number methods should return identical raw bytes"
        );

        // Verify consistency: raw bytes are same from mempool and confirmed
        assert_eq!(
            raw_tx1_confirmed_fn.unwrap(),
            raw_tx1_mempool_fn.unwrap(),
            "Raw tx bytes should be identical whether fetched from mempool or confirmed block"
        );

        // === Edge cases ===
        // getRawTransactionByHash: non-existent hash on both nodes
        let random_hash = TxHash::random();
        assert!(full_node_test_client
            .eth_get_raw_transaction_by_hash(random_hash, None)
            .await
            .is_none());
        assert!(seq_test_client
            .eth_get_raw_transaction_by_hash(random_hash, None)
            .await
            .is_none());

        // Block-based edge cases (same code path, only test on full node)
        assert!(full_node_test_client
            .eth_get_raw_tx_by_block_hash_and_index(B256::ZERO, U64::from(0))
            .await
            .is_none());
        assert!(full_node_test_client
            .eth_get_raw_tx_by_block_hash_and_index(block.header.hash, U64::from(99))
            .await
            .is_none());
        assert!(full_node_test_client
            .eth_get_raw_tx_by_block_number_and_index(BlockNumberOrTag::Number(1), U64::from(99))
            .await
            .is_none());

        Ok(())
    }
}

#[tokio::test]
async fn test_get_raw_transaction() -> Result<()> {
    TestCaseRunner::new(GetRawTransactionTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
