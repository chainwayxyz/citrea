use async_trait::async_trait;
use bitcoin::{Amount, Transaction};
use bitcoin_da::REVEAL_OUTPUT_AMOUNT;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, FINALITY_DEPTH};
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::sequencer::Sequencer;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;

use super::get_citrea_path;

/// Tests sequencer's transaction chaining across multiple batches and sequencer restart
///
/// # Flow
/// 1. Verifies chaining between TX2->TX3 in first batch
/// 2. Verifies cross-batch chaining (TX4->TX3, TX5->TX4) in second batch
/// 3. Restarts sequencer and verifies chaining persists (TX6->TX5, TX7->TX6)
///
/// Each batch should maintain consistent output values:
/// - Commit tx: Output equals reveal tx vsize in bytes * reveal_fee_rate (1 sat/vbyte fee fixed in regtest) + REVEAL_OUTPUT_AMOUNT
/// - Reveal tx: REVEAL_OUTPUT_AMOUNT
///
/// Test for chaining persistence and ordering and chain integrity survive sequencer restarts.
struct TestSequencerTransactionChaining;

impl TestSequencerTransactionChaining {
    fn get_reveal_tx_input_value(&self, reveal_tx: &Transaction) -> Amount {
        Amount::from_sat(reveal_tx.vsize() as u64 + REVEAL_OUTPUT_AMOUNT)
    }
}

#[async_trait]
impl TestCase for TestSequencerTransactionChaining {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(1).await?;

        // Get latest block
        let block = da.get_block(&da.get_best_block_hash().await?).await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx1 = &txs[1];
        let tx2 = &txs[2];

        assert_eq!(
            tx2.input[0].previous_output.txid,
            tx1.compute_txid(),
            "TX2 should reference TX1's output"
        );

        // Verify output values
        assert!(tx1.output[0].value >= self.get_reveal_tx_input_value(tx2));
        assert!(tx2.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        // Generate seqcommitment txs and make sure second batch is chained from first batch
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(1).await?;

        // Get latest block
        let block = da.get_block(&da.get_best_block_hash().await?).await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx3 = &txs[1];
        let tx4 = &txs[2];

        assert_eq!(
            tx3.input[0].previous_output.txid,
            tx2.compute_txid(),
            "TX3 should reference TX2's output"
        );

        assert_eq!(
            tx4.input[0].previous_output.txid,
            tx3.compute_txid(),
            "TX4 should reference TX3's output"
        );

        // Verify output values
        assert!(tx3.output[0].value >= self.get_reveal_tx_input_value(tx4));
        assert!(tx4.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        let last_tx = self
            .test_restart_with_empty_mempool(sequencer, da, tx4)
            .await?;

        self.test_restart_with_tx_in_mempool(sequencer, da, &last_tx)
            .await?;

        Ok(())
    }
}

impl TestSequencerTransactionChaining {
    async fn test_restart_with_empty_mempool(
        &self,
        sequencer: &mut Sequencer,
        da: &BitcoinNode,
        prev_tx: &Transaction,
    ) -> Result<Transaction> {
        // Start with empty mempool
        let mempool = da.get_raw_mempool().await?;
        assert_eq!(mempool.len(), 0);

        sequencer.restart(None).await?;

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // Generate seqcommitment txs restart and make sure third batch is chained from prev_tx
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(1).await?;

        // Get latest block
        let block = da.get_block(&da.get_best_block_hash().await?).await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx1 = &txs[1];
        let tx2 = &txs[2];

        assert_eq!(
            tx1.input[0].previous_output.txid,
            prev_tx.compute_txid(),
            "TX1 should reference prev_tx output"
        );

        assert_eq!(
            tx2.input[0].previous_output.txid,
            tx1.compute_txid(),
            "TX2 should reference TX1's output"
        );

        // Verify output values
        assert!(tx1.output[0].value >= self.get_reveal_tx_input_value(tx2));
        assert!(tx2.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        Ok(tx2.clone())
    }

    async fn test_restart_with_tx_in_mempool(
        &self,
        sequencer: &mut Sequencer,
        da: &BitcoinNode,
        prev_tx: &Transaction,
    ) -> Result<()> {
        // Start with empty mempool
        let mempool = da.get_raw_mempool().await?;
        assert_eq!(mempool.len(), 0);

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // Generate seqcommitment txs and check that they are chained from prev_tx
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Restart before generating a block to check `get_prev_utxo` prioritisting UTXO from mempool
        sequencer.restart(None).await?;

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(4, None).await?;

        // Generate two round of commit/reveal tx pair
        da.generate(1).await?;

        // Get latest block
        let block = da.get_block(&da.get_best_block_hash().await?).await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 5, "Block should contain exactly 5 transactions");

        let _coinbase = &txs[0];
        let tx1 = &txs[1];
        let tx2 = &txs[2];
        let tx3 = &txs[3];
        let tx4 = &txs[4];

        assert_eq!(
            tx1.input[0].previous_output.txid,
            prev_tx.compute_txid(),
            "TX5 should reference prev_tx output"
        );

        assert_eq!(
            tx2.input[0].previous_output.txid,
            tx1.compute_txid(),
            "TX2 should reference TX1's output"
        );

        assert_eq!(
            tx3.input[0].previous_output.txid,
            tx2.compute_txid(),
            "TX3 should reference TX2's output"
        );
        assert_eq!(
            tx4.input[0].previous_output.txid,
            tx3.compute_txid(),
            "TX4 should reference TX3's output"
        );

        // Verify output values
        assert!(tx1.output[0].value >= self.get_reveal_tx_input_value(tx2));
        assert!(tx2.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));
        assert!(tx3.output[0].value >= self.get_reveal_tx_input_value(tx4));
        assert!(tx4.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_transaction_chaining() -> Result<()> {
    TestCaseRunner::new(TestSequencerTransactionChaining)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct TestProverTransactionChaining;

impl TestProverTransactionChaining {
    fn get_reveal_tx_input_value(&self, reveal_tx: &Transaction) -> Amount {
        Amount::from_sat(reveal_tx.vsize() as u64 + REVEAL_OUTPUT_AMOUNT)
    }
}

#[async_trait]
impl TestCase for TestProverTransactionChaining {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height().await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.generate(1).await?;
        let block_height = da.get_block_count().await?;

        // Get block holding prover txs
        let block = da
            .get_block(&da.get_block_hash(block_height).await?)
            .await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx1 = &txs[1];
        let tx2 = &txs[2];

        assert_eq!(
            tx2.input[0].previous_output.txid,
            tx1.compute_txid(),
            "TX2 should reference TX1's output"
        );

        // Verify output values
        assert!(tx1.output[0].value >= self.get_reveal_tx_input_value(tx2));
        assert!(tx2.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        // // Do another round and make sure second batch is chained from first batch
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height().await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.generate(1).await?;
        let block_height = da.get_block_count().await?;

        // Get block holding prover txs
        let block = da
            .get_block(&da.get_block_hash(block_height).await?)
            .await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx3 = &txs[1];
        let tx4 = &txs[2];

        assert_eq!(
            tx4.input[0].previous_output.txid,
            tx3.compute_txid(),
            "TX4 should reference TX3's output"
        );

        // Verify output values
        assert!(tx3.output[0].value >= self.get_reveal_tx_input_value(tx4));
        assert!(tx4.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        batch_prover.restart(None).await?;

        // // Do another round post restart and make sure third batch is chained from second batch
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height().await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.generate(1).await?;
        let block_height = da.get_block_count().await?;

        // Get block holding prover txs
        let block = da
            .get_block(&da.get_block_hash(block_height).await?)
            .await?;
        let txs = &block.txdata;

        assert_eq!(txs.len(), 3, "Block should contain exactly 3 transactions");

        let _coinbase = &txs[0];
        let tx5 = &txs[1];
        let tx6 = &txs[2];

        assert_eq!(
            tx6.input[0].previous_output.txid,
            tx5.compute_txid(),
            "TX6 should reference TX5's output"
        );

        // Verify output values
        assert!(tx5.output[0].value >= self.get_reveal_tx_input_value(tx6));
        assert!(tx6.output[0].value >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT));

        Ok(())
    }
}

#[tokio::test]
async fn test_prover_transaction_chaining() -> Result<()> {
    TestCaseRunner::new(TestProverTransactionChaining)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
