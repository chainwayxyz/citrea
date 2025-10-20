use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::{env, fs};

use alloy_primitives::U32;
use anyhow::bail;
use async_trait::async_trait;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BitcoinConfig, SequencerConfig, SequencerMempoolConfig, TestCaseConfig, TestCaseEnv,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_sequencer::SequencerRpcClient;
use risc0_zkvm::{default_prover, ExecutorEnvBuilder, ProveInfo, ProverOpts};
use sov_ledger_rpc::LedgerRpcClient;

use crate::bitcoin::get_citrea_path;

/// Helper test to generate a batch proof input. Risc0 host code should be modified
/// to save the input to a file if it will be used in `guest_cycles` test. If the input
/// struct has not changed, you don't need to run this, and you can just use the one at
/// 'test-data/kumquat-input.bin'
struct GenerateProofInput {
    transactions_file_path: PathBuf,
}

#[async_trait]
impl TestCase for GenerateProofInput {
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
            max_l2_blocks_per_commitment: 150,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 1_000_000,
                pending_tx_size: 100_000_000,
                queue_tx_limit: 1_000_000,
                queue_tx_size: 100_000_000,
                base_fee_tx_limit: 1_000_000,
                base_fee_tx_size: 100_000_000,
                max_account_slots: 1_000_000,
            },
            ..Default::default()
        }
    }

    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![("RISC0_DEV_MODE", "1")],
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        let file = File::open(&self.transactions_file_path).unwrap();
        let reader = BufReader::new(file);
        let signed_txs = reader.lines().map(|line| line.unwrap()).collect::<Vec<_>>();
        let mut signed_txs_iter = signed_txs.iter().filter(|tx| !tx.trim().is_empty());

        // 2 full commitments
        // simulating 10 mins
        let blocks = 300;
        let tx_per_block = signed_txs.len() as u64 / blocks + 1;

        for block in 1..=blocks {
            for _ in 0..tx_per_block {
                let Some(signed_tx) = signed_txs_iter.next() else {
                    break;
                };

                sequencer
                    .client
                    .http_client()
                    .eth_send_raw_transaction(hex::decode(signed_tx).unwrap().into())
                    .await
                    .unwrap();
            }

            // if last block, ensure all txs are in the mempool
            if block == blocks {
                for signed_tx in signed_txs_iter.by_ref() {
                    sequencer
                        .client
                        .http_client()
                        .eth_send_raw_transaction(hex::decode(signed_tx).unwrap().into())
                        .await
                        .unwrap();
                }
            }

            // wait short time to ensure all txs are in the mempool
            tokio::time::sleep(Duration::from_millis(50)).await;

            sequencer.client.send_publish_batch_request().await.unwrap();

            sequencer.wait_for_l2_height(block, None).await?;
        }
        println!("All txs sent");

        // ensure commitment sent
        sequencer.client.send_publish_batch_request().await.unwrap();
        sequencer.client.send_publish_batch_request().await.unwrap();

        da.wait_mempool_len(4, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // passing in finality depth as this test should be run without testing feature
        let finalized_height = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await
            .unwrap();

        println!("Waiting batch prover l1 height: {finalized_height}");
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(100_800)))
            .await?;

        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn generate_proof_input() -> Result<()> {
    // Specify the path to your transactions file here
    let transactions_file_path = PathBuf::from("tests/bitcoin/test-data/signed-transactions.txt");

    TestCaseRunner::new(GenerateProofInput {
        transactions_file_path,
    })
    .set_citrea_path(env::var("CITREA_E2E_TEST_BINARY")?)
    .run()
    .await
}

#[tokio::test]
#[ignore]
async fn guest_cycles() {
    let input = fs::read("tests/bitcoin/test-data/kumquat-input.bin").unwrap();
    println!("Input size: {}", input.len());

    let elf_path = match env::var("ELF_PATH") {
        Ok(elf_path) => elf_path.into(),
        Err(_) => {
            // Convert tmpdir to path so it's not deleted after the run for debugging purposes
            let tmpdir = tempfile::tempdir().unwrap().keep();

            let mut elf_path = tmpdir.clone();
            elf_path.push("batch_proof_bitcoin");

            // Build guest elf with nightly network
            let status = Command::new("make")
                .arg("batch-proof-bitcoin-docker")
                .current_dir("../../guests/risc0")
                .env("CITREA_NETWORK", "nightly")
                .env("OUT_PATH", &elf_path)
                .status()
                .expect("'make batch-proof-bitcoin-docker' command failed");
            assert!(status.success());

            elf_path
        }
    };

    println!("\nELF path: {elf_path:?}");
    let elf = fs::read(elf_path).unwrap();

    let exec_env = ExecutorEnvBuilder::default()
        .write_slice(&input)
        .build()
        .unwrap();

    env::set_var("RISC0_DEV_MODE", "1");
    env::set_var("RISC0_INFO", "1");
    env::set_var("RUST_LOG", "info");
    env::set_var("RISC0_PPROF_OUT", "profile.pb");
    let prover = default_prover();

    println!("Started proving at {}", chrono::Local::now());
    let ProveInfo { stats, .. } = prover
        .prove_with_opts(exec_env, &elf, &ProverOpts::groth16())
        .unwrap();

    println!("Execution stats: {stats:?}");
}

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
            .map_err(|e| anyhow::anyhow!("Failed to open transactions file: {}", e))?;
        let reader = BufReader::new(file);

        // Send each transaction from the file
        let mut tx_count = 0;
        for (i, line) in reader.lines().enumerate() {
            let signed_tx =
                line.map_err(|e| anyhow::anyhow!("Failed to read line {}: {}", i, e))?;
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
