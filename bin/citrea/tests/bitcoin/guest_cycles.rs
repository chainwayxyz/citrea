use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use alloy_primitives::U32;
use anyhow::bail;
use async_trait::async_trait;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{BitcoinConfig, SequencerConfig, SequencerMempoolConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_sequencer::SequencerRpcClient;
use sov_ledger_rpc::LedgerRpcClient;

use crate::bitcoin::get_citrea_path;

/// This test generates a proving stats database by running transactions through the sequencer
/// and ensuring two commitments are published to Bitcoin before freezing the state.
/// We use the sequencer DB and bitcoin data dir in the proving stats workflow.
///
/// As we use the citrea artifact built without the testing feature in CI,
/// this test should be run without the testing feature as well.
/// This can be achieved by running with docker image citrea-dev
struct GenerateProvingStatsDB;
#[async_trait]
impl TestCase for GenerateProvingStatsDB {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            genesis_dir: Some(format!(
                "{}/tests/bitcoin/test-data/gen-proof-input-genesis",
                env!("CARGO_MANIFEST_DIR")
            )),
            ..Default::default()
        }
    }
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 24,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 1_000_000,
                pending_tx_size: 100000,
                queue_tx_limit: 1_000_000,
                queue_tx_size: 4000000,
                base_fee_tx_limit: 200_00000,
                base_fee_tx_size: 400000,
                max_account_slots: 100_000,
                ..Default::default()
            },
            test_mode: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-limitancestorcount=999", "-limitdescendantcount=999"],
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().expect("Sequencer not running");
        let batch_prover = f.batch_prover.as_ref().expect("Batch prover not running");
        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running")
        };

        // Read and send transactions from file
        let transactions_file_path = PathBuf::from(format!(
            "{}/tests/bitcoin/test-data/4tps-transactions.txt",
            env!("CARGO_MANIFEST_DIR")
        ));
        let file = File::open(transactions_file_path)
            .map_err(|e| anyhow::anyhow!("Failed to open transactions file: {e}"))?;
        let reader = BufReader::new(file);

        // Send each transaction from the file
        let mut tx_count = 0;
        for (i, line) in reader.lines().enumerate() {
            let signed_tx = line.map_err(|e| anyhow::anyhow!("Failed to read line {i}: {e}"))?;
            // Skip empty lines
            if signed_tx.trim().is_empty() {
                continue;
            }

            sequencer
                .client
                .http_client()
                .eth_send_raw_transaction(hex::decode(signed_tx.trim()).unwrap().into())
                .await?;

            tx_count += 1;
            if tx_count % 50 == 0 {
                let l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
                sequencer.client.send_publish_batch_request().await?;
                // ensure that the sequencer has published a batch
                sequencer.wait_for_l2_height(l2_height + 1, None).await?;
            }
        }
        for _ in 0..10 {
            let l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
            sequencer.client.send_publish_batch_request().await?;
            sequencer.wait_for_l2_height(l2_height + 1, None).await?;
        }
        // Expecting two commitments to be published
        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        batch_prover
            .wait_for_l1_height(da.get_finalized_height(None).await?, None)
            .await?;
        let commitments = futures::future::try_join_all([1, 2, 3].map(|i| {
            batch_prover
                .client
                .http_client()
                .get_sequencer_commitment_by_index(U32::from(i))
        }))
        .await?;
        assert!(commitments[0].is_some());
        assert!(commitments[1].is_some());
        assert!(commitments[2].is_none());

        Ok(())
    }
}

#[ignore = "Used for generating proving stats database, not a regular test"]
#[tokio::test(flavor = "multi_thread")]
async fn generate_proving_stats_db() -> Result<()> {
    TestCaseRunner::new(GenerateProvingStatsDB)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
