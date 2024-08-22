use anyhow::bail;
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;

use crate::bitcoin_e2e::config::TestCaseConfig;
use crate::bitcoin_e2e::config::{default_sequencer_config, ProverConfig, SequencerConfig};
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::sequencer::Sequencer;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates soft confirmations and wait until it reaches the first commitment.
/// It asserts that the blob inscribe txs have been sent.
/// This catches regression to the default prover flow, such as the one introduced by [#942](https://github.com/chainwayxyz/citrea/pull/942) and [#973](https://github.com/chainwayxyz/citrea/pull/973)
struct BasicProverTest;

#[async_trait]
impl TestCase for BasicProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_prover: true,
            ..Default::default()
        }
    }

    fn prover_config() -> ProverConfig {
        ProverConfig {
            proof_sampling_number: 0,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 10,
            test_mode: true,
            ..default_sequencer_config()
        }
    }

    async fn run_test(&self, f: &TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(prover) = &f.prover else {
            bail!("Prover not running. Set TestCaseConfig with_prover to true")
        };

        let Some(da) = f.nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind running as DA")
        };

        // Generate confirmed UTXOs
        da.generate(120, None).await?;

        let seq_height0 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height0, 0);

        for _ in 0..10 {
            sequencer.client.send_publish_batch_request().await;
        }

        da.generate(5, None).await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(1, None).await?;

        Ok(())
    }
}

#[tokio::test]
async fn basic_prover_test() -> Result<()> {
    TestCaseRunner::new(BasicProverTest).run().await
}
