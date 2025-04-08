use std::net::SocketAddr;
use std::time::{Duration, Instant};

use alloy_primitives::{Address, U32, U64};
use anyhow::bail;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::RpcApi;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_e2e::config::{
    BatchProverConfig, ProverGuestRunConfig, SequencerConfig, SequencerMempoolConfig,
    TestCaseConfig, TestCaseEnv,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::{BatchProver, FullNode};
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::rpc::{JobRpcResponse, VerifiedBatchProofResponse};
use tokio::time::sleep;
use uuid::Uuid;

use super::get_citrea_path;
use crate::common::make_test_client;

pub async fn wait_for_zkproofs(
    full_node: &FullNode,
    height: u64,
    timeout: Option<Duration>,
    count: usize,
) -> Result<Vec<VerifiedBatchProofResponse>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(240));

    loop {
        if start.elapsed() >= timeout {
            bail!("FullNode failed to get zkproofs within the specified timeout");
        }

        match full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(height))
            .await?
        {
            Some(proofs) => {
                if proofs.len() >= count {
                    return Ok(proofs);
                }
            }
            None => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Wait for prover job to finish.
pub async fn wait_for_prover_job(
    batch_prover: &BatchProver,
    job_id: Uuid,
    timeout: Option<Duration>,
) -> Result<JobRpcResponse> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(300));
    loop {
        let response = batch_prover
            .client
            .http_client()
            .get_proving_job(job_id)
            .await?;
        if let Some(response) = response {
            if let Some(proof) = &response.proof {
                if proof.l1_tx_id.is_some() {
                    return Ok(response);
                }
            }
        }

        let now = Instant::now();
        if start + timeout <= now {
            bail!("Timeout. Failed to get prover job {}", job_id);
        }

        sleep(Duration::from_secs(1)).await;
    }
}

pub async fn wait_for_prover_job_count(
    batch_prover: &BatchProver,
    count: usize,
    timeout: Option<Duration>,
) -> Result<Vec<Uuid>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(240));

    loop {
        if start.elapsed() >= timeout {
            bail!(
                "BatchProver failed to reach proving job count {} on time",
                count
            );
        }

        let job_ids = batch_prover
            .client
            .http_client()
            .get_proving_jobs(count)
            .await
            .unwrap();
        if job_ids.len() >= count {
            return Ok(job_ids);
        }

        sleep(Duration::from_millis(500)).await;
    }
}

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates l2 blocks and wait until it reaches the first commitment.
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

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(4, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        full_node.wait_for_l1_height(finalized_height, None).await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + FINALITY_DEPTH,
            Some(Duration::from_secs(120)),
            1,
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
                citrea_primitives::compression::compress_blob(&borshed_state_diff)?;
            println!(
                "StateDiff: size {}, compressed {}",
                state_diff_size,
                compressed_state_diff.len()
            );
        }

        let index_range = proofs[0].proof_output.sequencer_commitment_index_range;
        let index_range = (index_range.0.to::<u32>(), index_range.1.to::<u32>());

        for (i, commitment_idx) in (index_range.0..=index_range.1).enumerate() {
            let commitment = full_node
                .client
                .http_client()
                .get_sequencer_commitment_by_index(U32::from(commitment_idx))
                .await?
                .unwrap();
            let l2_block = sequencer
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(commitment.l2_end_block_number))
                .await?
                .unwrap();
            let state_roots = proofs[0].proof_output.state_roots.clone();
            assert_eq!(state_roots[i + 1].0, l2_block.header.state_root.to_vec());
        }

        // Generate proof against seqcom not starting from genesis
        for _ in 0..max_l2_blocks_per_commitment * 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(4, None).await?;
        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        full_node.wait_for_l1_height(finalized_height, None).await?;

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

// TODO: Should I remove this?
// #[derive(Default)]
// struct SkipPreprovenCommitmentsTest {
//     task_manager: TaskManager<()>,
// }

// #[async_trait]
// impl TestCase for SkipPreprovenCommitmentsTest {
//     fn test_config() -> TestCaseConfig {
//         TestCaseConfig {
//             with_batch_prover: true,
//             with_full_node: true,
//             ..Default::default()
//         }
//     }

//     fn sequencer_config() -> SequencerConfig {
//         SequencerConfig {
//             max_l2_blocks_per_commitment: 1,
//             ..Default::default()
//         }
//     }

//     fn scan_l1_start_height() -> Option<u64> {
//         Some(170)
//     }

//     async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
//         let da = f.bitcoin_nodes.get(0).unwrap();
//         let sequencer = f.sequencer.as_ref().unwrap();
//         let batch_prover = f.batch_prover.as_ref().unwrap();
//         let full_node = f.full_node.as_ref().unwrap();

//         let da_config = &f.bitcoin_nodes.get(0).unwrap().config;
//         let bitcoin_da_service_config = BitcoinServiceConfig {
//             node_url: format!(
//                 "http://127.0.0.1:{}/wallet/{}",
//                 da_config.rpc_port,
//                 NodeKind::Bitcoin
//             ),
//             node_username: da_config.rpc_user.clone(),
//             node_password: da_config.rpc_password.clone(),
//             network: bitcoin::Network::Regtest,
//             da_private_key: Some(
//                 // This is because the prover has a check to make sure that the commitment was
//                 // submitted by the sequencer and NOT any other key. Which means that arbitrary keys
//                 // CANNOT submit preproven commitments.
//                 // Using the sequencer DA private key means that we simulate the fact that the sequencer
//                 // somehow resubmitted the same commitment.
//                 sequencer
//                     .config()
//                     .rollup
//                     .da
//                     .da_private_key
//                     .as_ref()
//                     .unwrap()
//                     .clone(),
//             ),
//             tx_backup_dir: Self::test_config()
//                 .dir
//                 .join("tx_backup_dir")
//                 .display()
//                 .to_string(),
//             monitoring: Default::default(),
//             mempool_space_url: None,
//         };
//         let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

//         let bitcoin_da_service = Arc::new(
//             BitcoinService::new_with_wallet_check(
//                 bitcoin_da_service_config,
//                 RollupParams {
//                     reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
//                 },
//                 tx,
//             )
//             .await
//             .unwrap(),
//         );

//         self.task_manager
//             .spawn(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

//         // Generate FINALIZED DA block.
//         da.generate(FINALITY_DEPTH).await?;

//         let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

//         for _ in 0..max_l2_blocks_per_commitment {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         // Wait for blob inscribe tx to be in mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(FINALITY_DEPTH).await?;

//         let finalized_height = da.get_finalized_height(None).await?;
//         batch_prover
//             .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
//             .await?;

//         // Wait for batch proof tx to hit mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(FINALITY_DEPTH).await?;
//         let _proofs = wait_for_zkproofs(full_node, finalized_height + FINALITY_DEPTH, None, 1)
//             .await
//             .unwrap();

//         // TODO: this test will need refactor
//         // assert!(proofs
//         //     .first()
//         //     .unwrap()
//         //     .proof_output
//         //     .preproven_commitments
//         //     .is_empty());

//         // Make sure the mempool is mined.
//         da.wait_mempool_len(0, None).await?;

//         // Fetch the commitment created from the previous L1 range
//         let commitments: Vec<SequencerCommitment> = full_node
//             .client
//             .http_client()
//             .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height))
//             .await
//             .unwrap_or_else(|_| {
//                 panic!(
//                     "Failed to get sequencer commitments at {}",
//                     finalized_height
//                 )
//             })
//             .unwrap_or_else(|| panic!("No sequencer commitments found at {}", finalized_height))
//             .into_iter()
//             .map(|response| SequencerCommitment {
//                 merkle_root: response.merkle_root,
//                 index: response.index.to(),
//                 l2_end_block_number: response.l2_end_block_number.to(),
//             })
//             .collect();

//         // Send the same commitment that was already proven.
//         bitcoin_da_service
//             .send_transaction_with_fee_rate(
//                 DaTxRequest::SequencerCommitment(commitments.first().unwrap().clone()),
//                 1,
//             )
//             .await
//             .unwrap();

//         // Wait for the duplicate commitment transaction to be accepted.
//         da.wait_mempool_len(2, None).await?;

//         Trigger a new commitment.
//         for _ in 0..max_l2_blocks_per_commitment {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         // Wait for the sequencer commitment to be submitted & accepted.
//         da.wait_mempool_len(4, None).await?;

//         da.generate(FINALITY_DEPTH).await?;
//         let finalized_height = da.get_finalized_height(None).await?;

//         batch_prover
//             .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
//             .await?;

//         // Wait for batch proof tx to hit mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(FINALITY_DEPTH).await?;
//         let finalized_height = da.get_finalized_height(None).await?;

//         // Wait for the full node to see all process verify and store all batch proofs
//         full_node.wait_for_l1_height(finalized_height, None).await?;
//         let _proofs = wait_for_zkproofs(
//             full_node,
//             finalized_height,
//             Some(Duration::from_secs(600)),
//             1,
//         )
//         .await
//         .unwrap();

//         // TODO: this test will need refactor
//         // assert_eq!(
//         //     proofs
//         //         .first()
//         //         .unwrap()
//         //         .proof_output
//         //         .preproven_commitments
//         //         .len(),
//         //     1
//         // );

//         Ok(())
//     }

//     async fn cleanup(self) -> Result<()> {
//         self.task_manager.abort().await;
//         Ok(())
//     }
// }

// #[tokio::test]
// async fn prover_skips_preproven_commitments_test() -> Result<()> {
//     TestCaseRunner::new(SkipPreprovenCommitmentsTest::default())
//         .set_citrea_path(get_citrea_path())
//         .run()
//         .await
// }

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
            test: vec![("BONSAI_API_URL", ""), ("BONSAI_API_KEY", "")],
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
            max_l2_blocks_per_commitment: 1,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        // citrea::initialize_logging(tracing::Level::INFO);

        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        // Generate l2 blocks to invoke commitment creation
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for commitment tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make commitment tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for batch prover to process the proof
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(7200)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make batch proof tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to see zkproofs
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height,
            Some(Duration::from_secs(7200)),
            1,
        )
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

struct ParallelProvingTest;

#[async_trait]
impl TestCase for ParallelProvingTest {
    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![("RISC0_DEV_MODE", "1"), ("PARALLEL_PROOF_LIMIT", "2")],
            ..Default::default()
        }
    }

    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 100,
            mempool_conf: SequencerMempoolConfig {
                max_account_slots: 1000,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        // Invoke 2 sequencer commitments
        for _ in 0..max_l2_blocks_per_commitment * 2 {
            // 6 txs in each block
            for _ in 0..6 {
                let _ = seq_test_client
                    .send_eth(Address::random(), None, None, None, 100)
                    .await
                    .unwrap();
            }

            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for 2 commitments (4 txs) to hit DA mempool
        da.wait_mempool_len(4, Some(Duration::from_secs(420)))
            .await?;

        // Write commitments to a finalized DA block
        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait until batch prover processes the commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof txs to hit mempool
        da.wait_mempool_len(4, Some(Duration::from_secs(420)))
            .await?;

        // Write 2 batch proofs (4 txs) to a finalized DA block
        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Retrieve proofs from fullnode
        let proofs = wait_for_zkproofs(full_node, finalized_height, None, 2)
            .await
            .unwrap();
        assert_eq!(proofs.len(), 2);

        Ok(())
    }
}

#[tokio::test]
async fn parallel_proving_test() -> Result<()> {
    TestCaseRunner::new(ParallelProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

// struct ForkElfSwitchingTest;

// #[async_trait]
// impl TestCase for ForkElfSwitchingTest {
//     fn test_config() -> TestCaseConfig {
//         TestCaseConfig {
//             with_batch_prover: true,
//             with_full_node: true,
//             with_light_client_prover: true,
//             mode: CitreaMode::DevAllForks,
//             ..Default::default()
//         }
//     }

//     fn light_client_prover_config() -> LightClientProverConfig {
//         LightClientProverConfig {
//             initial_da_height: 171,
//             enable_recovery: false,
//             ..Default::default()
//         }
//     }

//     fn sequencer_config() -> SequencerConfig {
//         let kumquat_height = ForkManager::new(get_forks(), 0)
//             .next_fork()
//             .unwrap()
//             .activation_height;

//         // Set just below kumquat height so we can generate first soft com txs in genesis
//         // and second batch above kumquat
//         SequencerConfig {
//             max_l2_blocks_per_commitment: kumquat_height - 5,
//             ..Default::default()
//         }
//     }

//     async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
//         let da = f.bitcoin_nodes.get(0).unwrap();
//         let sequencer = f.sequencer.as_ref().unwrap();
//         let batch_prover = f.batch_prover.as_ref().unwrap();
//         let full_node = f.full_node.as_ref().unwrap();
//         let light_client_prover = f.light_client_prover.as_ref().unwrap();

//         // send evm tx
//         let evm_client = make_test_client(SocketAddr::new(
//             sequencer.config().rpc_bind_host().parse()?,
//             sequencer.config().rpc_bind_port(),
//         ))
//         .await?;

//         let pending_evm_tx = evm_client
//             .send_eth(Address::random(), None, None, None, 100)
//             .await
//             .unwrap();

//         let min_l2_blocks = sequencer.max_l2_blocks_per_commitment();

//         for _ in 0..min_l2_blocks {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         // assert that evm tx is mined
//         let evm_tx = evm_client
//             .eth_get_transaction_by_hash(*pending_evm_tx.tx_hash(), None)
//             .await
//             .unwrap();

//         assert!(evm_tx.block_number.is_some());

//         let height = sequencer
//             .client
//             .ledger_get_head_l2_block_height()
//             .await?;

//         assert_eq!(fork_from_block_number(height).spec_id, SpecId::Genesis);

//         // Generate softcom in kumquat
//         for _ in 0..min_l2_blocks {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         let height = sequencer
//             .client
//             .ledger_get_head_l2_block_height()
//             .await?;
//         assert_eq!(fork_from_block_number(height).spec_id, SpecId::Kumquat);

//         // Generate softcom in fork2
//         for _ in 0..min_l2_blocks {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         let last_sc_before_fork2 = sequencer
//             .client
//             .http_client()
//             .get_l2_block_by_number(U64::from(199u64))
//             .await
//             .unwrap()
//             .unwrap();

//         // the last tx of last l2 block before fork2 should be the change authority sov tx
//         let last_tx_hex = last_sc_before_fork2
//             .clone()
//             .txs
//             .clone()
//             .unwrap()
//             .last()
//             .expect("should have last tx")
//             .clone();

//         let tx_vec = last_tx_hex.tx.clone();

//         let tx = Transaction::try_from_slice(&tx_vec).expect("Should be the tx");

//         let k256_pub_key_sequencer = K256PublicKey::try_from(
//             sequencer
//                 .config()
//                 .rollup
//                 .public_keys
//                 .sequencer_public_key
//                 .as_slice(),
//         )
//         .unwrap();

//         let address = k256_pub_key_sequencer.to_address::<<DefaultContext as Spec>::Address>();

//         // Going to ignore the first byte here because it's the call prefix
//         // It is an enum of modules:
//         // 0 is accounts,1 is evm, 2 is l2 block rule enforcer
//         // assert the first byte is 2 as in sc rule enforcer
//         assert_eq!(tx.runtime_msg()[0], 2);

//         let change_authority_call_message: l2_block_rule_enforcer::CallMessage
//         // Going to ignore the first byte here because it's the call prefix as explained above
//         = l2_block_rule_enforcer::CallMessage::try_from_slice(&tx.runtime_msg()[1..])
//             .expect("Should be the tx");

//         match change_authority_call_message {
//             l2_block_rule_enforcer::CallMessage::ChangeAuthority { new_authority } => {
//                 assert_eq!(new_authority, address);
//                 println!("New authority: {:?}", new_authority);
//             }
//             _ => panic!("Should be change authority"),
//         }

//         let height = sequencer
//             .client
//             .ledger_get_head_l2_block_height()
//             .await?;
//         assert_eq!(fork_from_block_number(height).spec_id, SpecId::Fork2);

//         da.wait_mempool_len(6, None).await?;

//         da.generate(FINALITY_DEPTH).await?;

//         let finalized_height = da.get_finalized_height(None).await?;

//         batch_prover
//             .wait_for_l1_height(finalized_height, None)
//             .await?;

//         // Wait for batch proof tx to hit mempool
//         da.wait_mempool_len(6, None).await?;
//         da.generate(FINALITY_DEPTH).await?;

//         full_node
//             .wait_for_l1_height(finalized_height + FINALITY_DEPTH, None)
//             .await?;
//         let proofs = wait_for_zkproofs(full_node, finalized_height + FINALITY_DEPTH, None, 3)
//             .await
//             .unwrap();

//         assert_eq!(proofs.len(), 3);
//         assert_eq!(
//             SpecId::from_u8(
//                 proofs[0]
//                     .proof_output
//                     .last_active_spec_id
//                     .expect("should have field")
//                     .to()
//             )
//             .expect("should be valid"),
//             SpecId::Genesis
//         );
//         assert_eq!(
//             fork_from_block_number(
//                 proofs[1]
//                     .proof_output
//                     .last_l2_height
//                     .expect("should have field")
//                     .to()
//             )
//             .spec_id,
//             SpecId::Kumquat
//         );
//         assert_eq!(
//             fork_from_block_number(proofs[2].proof_output.last_l2_height.unwrap().to()).spec_id,
//             SpecId::Fork2
//         );

//         light_client_prover
//             .wait_for_l1_height(finalized_height + FINALITY_DEPTH, None)
//             .await?;
//         let lcp = light_client_prover
//             .client
//             .http_client()
//             .get_light_client_proof_by_l1_height(finalized_height + FINALITY_DEPTH)
//             .await
//             .unwrap()
//             .unwrap();

//         assert!(lcp
//             .light_client_proof_output
//             .unchained_batch_proofs_info
//             .is_empty());

//         assert_eq!(
//             lcp.light_client_proof_output.l2_state_root.to_vec(),
//             proofs[2].proof_output.final_state_root
//         );

//         Ok(())
//     }
// }

// // ignoring this test now as we won't be supporting backwards compatability for proofs.
// #[tokio::test]
// #[ignore]
// async fn test_fork_elf_switching() -> Result<()> {
//     use_network_forks(Network::TestNetworkWithForks);

//     TestCaseRunner::new(ForkElfSwitchingTest)
//         .set_citrea_path(get_citrea_path())
//         .run()
//         .await
// }

struct L1HashOutputTest;

#[async_trait]
impl TestCase for L1HashOutputTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 12,
            ..Default::default()
        }
    }

    /// The test consists of two parts.
    /// Part 1 we make lots of DA blocks so the Bitcoin Light Client Contract gets updated many times
    /// in a single proof.
    /// Then we assert that the proof output has the latest L1 hash.
    ///
    /// Then we don't make any new DA blocks, make a single proof and assert that we still have
    /// the same L1 hash outputted.
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        sequencer.client.send_publish_batch_request().await?;
        let start_l1_height = da.get_finalized_height(None).await?;

        sequencer.client.wait_for_l2_block(1, None).await?;

        da.generate(100).await?; // This will produce ceil(100 - 1 / MAX_MISSED_DA_BLOCKS_PER_L2_BLOCK) l2 blocks post fork2 which is 10

        tokio::time::sleep(Duration::from_secs(2)).await;
        sequencer.client.send_publish_batch_request().await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        sequencer.client.send_publish_batch_request().await?;

        // Wait for commitment tx
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for prover to see the commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // Wait for proving job to start
        let job_ids = wait_for_prover_job_count(batch_prover, 1, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);
        let job_id = job_ids[0];

        // Wait for proving job to finish
        let response = wait_for_prover_job(batch_prover, job_id, None)
            .await
            .unwrap();
        let proof = response.proof.unwrap();

        let l1_hash = proof
            .proof_output
            .last_l1_hash_on_bitcoin_light_client_contract
            .clone();

        let hash_from_rpc = sequencer.da.get_block_hash(start_l1_height + 100).await?;

        assert_eq!(
            hash_from_rpc.as_raw_hash().to_byte_array().to_vec(),
            l1_hash
        );

        // part 2
        for _ in 0..26 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(6, None).await?;

        for _ in 0..13 {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(8, None).await?;

        let temp_addr = da
            .get_new_address(None, None)
            .await?
            .assume_checked()
            .to_string();

        let txs = da.get_raw_mempool().await?;

        let commitments_with_l1_update = txs[0..4].iter().map(|txid| txid.to_string()).collect();

        // First, finalize the commitments with l1 update
        da.generate_block(temp_addr, commitments_with_l1_update)
            .await?;
        da.generate(FINALITY_DEPTH - 1).await?;

        // Wait for 2nd proving job to start
        let job_ids = wait_for_prover_job_count(batch_prover, 2, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 2);

        // Wait for job to finish, job ids are descending order, so latest is in the first index
        let response_prev = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        let zkp_prev = response_prev.proof.unwrap();

        let prev_l1_hash = zkp_prev
            .proof_output
            .last_l1_hash_on_bitcoin_light_client_contract
            .clone();

        assert_ne!(prev_l1_hash, l1_hash);

        // Second, finalize the rest of the commitments
        da.generate(1).await?;

        // Wait for 3rd proving job to start
        let job_ids = wait_for_prover_job_count(batch_prover, 3, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 3);

        // Wait for last proving to finish
        let response_last = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        let zkp_last = response_last.proof.unwrap();

        let new_l1_hash = zkp_last
            .proof_output
            .last_l1_hash_on_bitcoin_light_client_contract
            .clone();

        assert_eq!(new_l1_hash, prev_l1_hash);

        Ok(())
    }
}

#[tokio::test]
async fn test_batch_proof_l1_hashes_added_output() -> Result<()> {
    TestCaseRunner::new(L1HashOutputTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
