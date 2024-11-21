use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use async_trait::async_trait;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, FINALITY_DEPTH};
use bitcoin_da::spec::RollupParams;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::{
    BatchProverConfig, ProverGuestRunConfig, SequencerConfig, TestCaseConfig, TestCaseEnv,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::full_node::FullNode;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_ledger_rpc::client::RpcClient;
use sov_rollup_interface::da::{DaData, SequencerCommitment};
use sov_rollup_interface::rpc::VerifiedBatchProofResponse;
use tokio::time::sleep;

use super::get_citrea_path;

pub async fn wait_for_zkproofs(
    full_node: &FullNode,
    height: u64,
    timeout: Option<Duration>,
) -> Result<Vec<VerifiedBatchProofResponse>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(30));

    loop {
        if start.elapsed() >= timeout {
            bail!("FullNode failed to get zkproofs within the specified timeout");
        }

        match full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(height)
            .await?
        {
            Some(proofs) => return Ok(proofs),
            None => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates soft confirmations and wait until it reaches the first commitment.
/// It asserts that the blob inscribe txs have been sent.
/// This catches regression to the default prover flow, such as the one introduced by [#942](https://github.com/chainwayxyz/citrea/pull/942) and [#973](https://github.com/chainwayxyz/citrea/pull/973)
struct BasicProverTest;

#[async_trait]
impl TestCase for BasicProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 10,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(batch_prover) = &f.batch_prover else {
            bail!("Batch Prover not running. Set TestCaseConfig with_batch_prover to true")
        };

        let Some(full_node) = &f.full_node else {
            bail!("FullNode not running. Set TestCaseConfig with_full_node to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind running as DA")
        };

        // Generate confirmed UTXOs
        da.generate(120).await?;

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.generate(FINALITY_DEPTH).await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height().await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.generate(FINALITY_DEPTH).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + FINALITY_DEPTH,
            Some(Duration::from_secs(120)),
        )
        .await
        .unwrap();

        {
            // print some debug info about state diff
            let state_diff = &proofs[0].proof_output.state_diff;
            let state_diff_size: usize = state_diff
                .iter()
                .map(|(k, v)| k.len() + v.as_ref().map(|v| v.len()).unwrap_or_default())
                .sum();
            let borshed_state_diff = borsh::to_vec(state_diff).unwrap();
            let compressed_state_diff =
                citrea_primitives::compression::compress_blob(&borshed_state_diff);
            println!(
                "StateDiff: size {}, compressed {}",
                state_diff_size,
                compressed_state_diff.len()
            );
        }

        Ok(())
    }
}

#[tokio::test]
async fn basic_prover_test() -> Result<()> {
    TestCaseRunner::new(BasicProverTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct SkipPreprovenCommitmentsTest {
    task_manager: TaskManager<()>,
}

#[async_trait]
impl TestCase for SkipPreprovenCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(prover) = &f.batch_prover else {
            bail!("Batch Prover not running. Set TestCaseConfig with_batch_prover to true")
        };

        let Some(full_node) = &f.full_node else {
            bail!("FullNode not running. Set TestCaseConfig with_full_node to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind running as DA")
        };

        let _initial_height = f.initial_da_height;

        let da_config = &f.bitcoin_nodes.get(0).unwrap().config;
        let bitcoin_da_service_config = BitcoinServiceConfig {
            node_url: format!(
                "http://127.0.0.1:{}/wallet/{}",
                da_config.rpc_port,
                NodeKind::Bitcoin
            ),
            node_username: da_config.rpc_user.clone(),
            node_password: da_config.rpc_password.clone(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                // This is the private key used by the sequencer.
                // This is because the prover has a check to make sure that the commitment was
                // submitted by the sequencer and NOT any other key. Which means that arbitrary keys
                // CANNOT submit preproven commitments.
                // Using the sequencer DA private key means that we simulate the fact that the sequencer
                // somehow resubmitted the same commitment.
                "045FFC81A3C1FDB3AF1359DBF2D114B0B3EFBF7F29CC9C5DA01267AA39D2C78D".to_owned(),
            ),
            tx_backup_dir: Self::test_config()
                .dir
                .join("tx_backup_dir")
                .display()
                .to_string(),
            monitoring: Default::default(),
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let bitcoin_da_service = Arc::new(
            BitcoinService::new_with_wallet_check(
                bitcoin_da_service_config,
                RollupParams {
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager
            .spawn(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

        // Generate 1 FINALIZED DA block.
        da.generate(1 + FINALITY_DEPTH).await?;

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.generate(FINALITY_DEPTH).await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height().await?;
        prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
            .await?;

        da.generate(FINALITY_DEPTH).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + FINALITY_DEPTH,
            Some(Duration::from_secs(120)),
        )
        .await
        .unwrap();

        assert!(proofs
            .first()
            .unwrap()
            .proof_output
            .preproven_commitments
            .is_empty());

        // Make sure the mempool is mined.
        da.wait_mempool_len(0, None).await?;

        // Fetch the commitment created from the previous L1 range
        let commitments: Vec<SequencerCommitment> = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(finalized_height)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to get sequencer commitments at {}",
                    finalized_height
                )
            })
            .unwrap_or_else(|| panic!("No sequencer commitments found at {}", finalized_height))
            .into_iter()
            .map(|response| SequencerCommitment {
                merkle_root: response.merkle_root,
                l2_start_block_number: response.l2_start_block_number,
                l2_end_block_number: response.l2_end_block_number,
            })
            .collect();

        // Send the same commitment that was already proven.
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaData::SequencerCommitment(commitments.first().unwrap().clone()),
                1,
            )
            .await
            .unwrap();

        // Wait for the duplicate commitment transaction to be accepted.
        da.wait_mempool_len(2, None).await?;

        // Trigger a new commitment.
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for the sequencer commitment to be submitted & accepted.
        da.wait_mempool_len(4, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height().await?;

        prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
            .await?;

        da.generate(FINALITY_DEPTH).await?;

        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + FINALITY_DEPTH,
            Some(Duration::from_secs(120)),
        )
        .await
        .unwrap();

        assert_eq!(
            proofs
                .first()
                .unwrap()
                .proof_output
                .preproven_commitments
                .len(),
            1
        );

        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }
}

#[tokio::test]
async fn prover_skips_preproven_commitments_test() -> Result<()> {
    TestCaseRunner::new(SkipPreprovenCommitmentsTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LocalProvingTest;

#[async_trait]
impl TestCase for LocalProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![
                ("CI_TEST_MODE", "1"),
                ("BONSAI_API_URL", ""),
                ("BONSAI_API_KEY", ""),
            ],
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Prove,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            // Made this 1 or-else proving takes forever
            min_soft_confirmations_per_commitment: 1,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        // citrea::initialize_logging(tracing::Level::INFO);

        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();
        // Generate soft confirmations to invoke commitment creation
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for commitment tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make commitment tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height().await?;
        // Wait for batch prover to process the proof
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(7200)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make batch proof tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height().await?;
        // Wait for full node to see zkproofs
        let proofs =
            wait_for_zkproofs(full_node, finalized_height, Some(Duration::from_secs(7200)))
                .await
                .unwrap();

        assert_eq!(proofs.len(), 1);

        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn local_proving_test() -> Result<()> {
    TestCaseRunner::new(LocalProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
