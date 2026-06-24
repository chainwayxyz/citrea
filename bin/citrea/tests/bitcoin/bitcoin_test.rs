use std::collections::HashMap;
use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use bitcoin_da::monitoring::TxStatus;
use bitcoin_da::rpc::DaRpcClient;
use bitcoincore_rpc::RpcApi;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use tokio::time::sleep;

use super::get_citrea_path;

struct BitcoinReorgTest;

#[async_trait]
impl TestCase for BitcoinReorgTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            n_nodes: HashMap::from([(NodeKind::Bitcoin, 2)]),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (Some(da0), Some(da1)) = (f.bitcoin_nodes.get(0), f.bitcoin_nodes.get(1)) else {
            bail!("Bitcoin nodes not running. Test requires two DA nodes")
        };

        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // Disconnect nodes before generating commitment
        f.bitcoin_nodes.disconnect_nodes().await?;

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for the sequencer commitments to hit the mempool
        da0.wait_mempool_len(2, None).await?;

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 2);
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 0);

        // Mine block with the sequencer commitment on the main chain
        da0.generate(1).await?;

        let original_chain_height = da0.get_block_count().await?;
        let original_chain_hash = da0.get_block_hash(original_chain_height).await?;
        let block = da0.get_block(&original_chain_hash).await?;
        assert_eq!(block.txdata.len(), 3); // Coinbase + seq commit/reveal txs

        // Buffer to wait for monitoring to update status to confirmed
        tokio::time::sleep(Duration::from_secs(2)).await;

        let da1_generated_blocks = 3;
        da1.generate(da1_generated_blocks).await?;

        // Reconnect nodes and wait for sync
        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Assert that re-org occurred
        let new_hash = da0.get_block_hash(original_chain_height).await?;
        assert_ne!(original_chain_hash, new_hash, "Re-org did not occur");

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 2);

        let pending_txs = sequencer
            .client
            .http_client()
            .da_get_pending_transactions()
            .await?;

        assert!(mempool0.contains(&pending_txs[0].txid));
        assert!(mempool0.contains(&pending_txs[1].txid));

        let tx_status = sequencer
            .client
            .http_client()
            .da_get_tx_status(mempool0[0])
            .await?;
        assert!(matches!(tx_status, Some(TxStatus::InMempool { .. })));

        da1.wait_mempool_len(2, None).await?;

        // Seq TXs should be rebroadcasted after re-org
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 2);

        da1.generate(1).await?;
        let height = da0.get_block_count().await?;
        let hash = da0.get_block_hash(height).await?;
        let block = da0.get_block(&hash).await?;
        assert_eq!(block.txdata.len(), 3); // Coinbase + seq commit/reveal txs

        da1.generate(DEFAULT_FINALITY_DEPTH - 1).await?;
        let finalized_height = da1.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Generate on da1 and wait for da0 to be back in sync
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Verify that commitments are included
        let original_commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(finalized_height)
            .await?
            .unwrap_or_default();

        assert_eq!(original_commitments.len(), 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_bitcoin_reorg() -> Result<()> {
    TestCaseRunner::new(BitcoinReorgTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct DaMonitoringTest;

#[async_trait]
impl TestCase for DaMonitoringTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for the sequencer commitments to hit the mempool
        da.wait_mempool_len(2, None).await?;

        let mempool0 = da.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 2);

        sleep(Duration::from_secs(1)).await;
        let pending_txs = sequencer
            .client
            .http_client()
            .da_get_pending_transactions()
            .await?;

        assert!(mempool0.contains(&pending_txs[0].txid));
        assert!(mempool0.contains(&pending_txs[1].txid));

        let tx_status = sequencer
            .client
            .http_client()
            .da_get_tx_status(mempool0[0])
            .await?;
        assert!(matches!(tx_status, Some(TxStatus::InMempool { .. })));

        let monitored_tx = sequencer
            .client
            .http_client()
            .da_get_monitored_transaction(pending_txs[0].txid, false)
            .await?;
        assert_eq!(pending_txs[0], monitored_tx.unwrap());

        let non_monitored_tx = sequencer
            .client
            .http_client()
            .da_get_monitored_transaction(Txid::all_zeros(), false)
            .await?;
        assert!(non_monitored_tx.is_none());

        da.generate(1).await?;

        sleep(Duration::from_secs(1)).await;
        let tx_status = sequencer
            .client
            .http_client()
            .da_get_tx_status(mempool0[0])
            .await?;
        assert!(matches!(tx_status, Some(TxStatus::Confirmed { .. })));

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        sleep(Duration::from_secs(1)).await;
        let tx_status = sequencer
            .client
            .http_client()
            .da_get_tx_status(mempool0[0])
            .await?;
        assert!(matches!(tx_status, Some(TxStatus::Finalized { .. })));

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for the sequencer commitments to hit the mempool
        da.wait_mempool_len(2, None).await?;
        let mempool0 = da.get_raw_mempool().await?;

        // Assert that txs are properly monitored
        let pending_txs = sequencer
            .client
            .http_client()
            .da_get_pending_transactions()
            .await?;

        assert!(mempool0.contains(&pending_txs[0].txid));
        assert!(mempool0.contains(&pending_txs[1].txid));

        sequencer.restart(None, None).await?;

        // Assert that txs are properly monitored after a restart
        let pending_txs = sequencer
            .client
            .http_client()
            .da_get_pending_transactions()
            .await?;

        assert!(mempool0.contains(&pending_txs[0].txid));
        assert!(mempool0.contains(&pending_txs[1].txid));

        Ok(())
    }
}

#[tokio::test]
async fn test_da_monitoring() -> Result<()> {
    TestCaseRunner::new(DaMonitoringTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
