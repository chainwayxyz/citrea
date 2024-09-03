use anyhow::bail;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::RpcApi;
use tokio::time::sleep;

use crate::bitcoin_e2e::config::{ProverConfig, SequencerConfig, TestCaseConfig};
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::L2Node;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

struct LedgerGetCommitmentsProverTest;

const MIN_SOFT_CONF_PER_COMMITMENT: u64 = 4;

#[async_trait]
impl TestCase for LedgerGetCommitmentsProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: MIN_SOFT_CONF_PER_COMMITMENT,
            da_update_interval_ms: 100,
            block_production_interval_ms: 100,
            ..Default::default()
        }
    }

    async fn run_test(&self, f: &TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let da = f.bitcoin_nodes.get(0).expect("DA not running.");

        let Some(prover) = &f.prover else {
            bail!("Prover not running. Set TestCaseConfig with_prover to true")
        };

        let initial_height = f.initial_da_height;

        for _ in 0..MIN_SOFT_CONF_PER_COMMITMENT {
            sequencer.client.send_publish_batch_request().await;
        }
        sequencer
            .wait_for_l2_height(MIN_SOFT_CONF_PER_COMMITMENT, None)
            .await;

        da.generate(10, None).await?;

        // wait for tx
        da.wait_mempool_len(1, None).await?;

        da.generate(5, None).await?;
        let finalized_height = da.get_finalized_height().await?;

        // wait here until we see from prover's rpc that it finished proving
        prover.wait_for_l1_height(finalized_height, None).await;

        let commitments = prover
            .client
            .ledger_get_sequencer_commitments_on_slot_by_number(finalized_height)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(commitments.len(), 1);

        assert_eq!(commitments[0].l2_start_block_number, 1);
        assert_eq!(commitments[0].l2_end_block_number, 4);

        assert_eq!(commitments[0].found_in_l1, finalized_height);

        let hash = da.get_block_hash(finalized_height).await?;

        let commitments_hash = prover
            .client
            .ledger_get_sequencer_commitments_on_slot_by_hash(hash.as_raw_hash().to_byte_array())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments_hash, commitments);
        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_prover() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsProverTest)
        .run()
        .await
}

struct LedgerGetCommitmentsTest;

#[async_trait]
impl TestCase for LedgerGetCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: MIN_SOFT_CONF_PER_COMMITMENT,
            ..Default::default()
        }
    }

    async fn run_test(&self, f: &TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };
        let da = f.bitcoin_nodes.get(0).expect("DA not running.");
        let Some(full_node) = &f.full_node else {
            bail!("Fullnode not running. Set TestCaseConfig with_full_node to true")
        };

        let initial_height = f.initial_da_height;

        for _ in 0..MIN_SOFT_CONF_PER_COMMITMENT {
            sequencer.client.send_publish_batch_request().await;
        }

        da.generate(5, None).await?;

        sequencer.client.send_publish_batch_request().await;

        da.generate(5, None).await?;

        // Wait for blob tx to hit the mempool
        da.wait_mempool_len(1, None).await?;

        // Generate enough block to finalize
        da.generate(5, None).await?;

        full_node
            .wait_for_l2_height(MIN_SOFT_CONF_PER_COMMITMENT + 1, None)
            .await;

        let finalized_height = da.get_finalized_height().await?;

        let commitments = full_node
            .wait_for_sequencer_commitments(finalized_height, None)
            .await?;

        assert_eq!(commitments.len(), 1);

        assert_eq!(commitments[0].l2_start_block_number, 1);
        assert_eq!(commitments[0].l2_end_block_number, 4);

        assert_eq!(commitments[0].found_in_l1, finalized_height);

        let hash = da.get_block_hash(finalized_height).await?;

        let commitments_hash = full_node
            .client
            .ledger_get_sequencer_commitments_on_slot_by_hash(hash.as_raw_hash().to_byte_array())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments_hash, commitments);
        Ok(())
    }
}

#[tokio::test]
async fn test_ledger_get_commitments_on_slot_full_node() -> Result<()> {
    TestCaseRunner::new(LedgerGetCommitmentsTest).run().await
}
