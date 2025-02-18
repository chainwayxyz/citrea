use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::{env, fs};

use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use citrea_e2e::config::{SequencerConfig, SequencerMempoolConfig, TestCaseConfig, TestCaseEnv};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_sequencer::SequencerRpcClient;
use risc0_zkvm::{default_prover, ExecutorEnvBuilder, ProveInfo, ProverOpts};

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
            min_soft_confirmations_per_commitment: 50,
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
        let blocks = sequencer.config.node.min_soft_confirmations_per_commitment * 2;
        let tx_per_block = signed_txs.len() as u64 / blocks;

        for block in 1..=blocks {
            for _ in 0..tx_per_block {
                let signed_tx = signed_txs_iter.next().unwrap();

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
        }
        println!("All txs sent");

        da.wait_mempool_len(4, None).await?;
        da.generate(FINALITY_DEPTH).await?;

        // passing in finality depth as this test should be run without testing feature
        let finalized_height = da.get_finalized_height(Some(FINALITY_DEPTH)).await.unwrap();

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
            let tmpdir = tempfile::tempdir().unwrap().into_path();

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

    println!("\nELF path: {:?}", elf_path);
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

    println!("Execution stats: {:?}", stats);
}
