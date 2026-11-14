use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

use alloy::consensus::{SignableTransaction, TxLegacy};
use alloy::network::TxSigner;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_primitives::{Address, Bytes, TxKind, U256, U32, U64};
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::PartitionMode;
use citrea_common::config::sp1::SP1HostConfig;
use citrea_common::FromEnv;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, LightClientProverConfig, SequencerConfig, SequencerMempoolConfig,
    TestCaseConfig, TestCaseEnv,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::{NodeT, Restart};
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use citrea_sequencer::SequencerRpcClient;
use citrea_sp1::host::SP1Host;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::Zkvm as _;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::{ProvingSessionInfo, ReceiptType, ZkvmHost};
use sov_rollup_interface::Network;
use uuid::Uuid;

use super::get_citrea_path;
use super::utils::wait_for_zkproofs;
use crate::bitcoin::utils::{wait_for_prover_job, wait_for_prover_job_count};
use crate::common::make_test_client;

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

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        full_node.wait_for_l1_height(finalized_height, None).await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + DEFAULT_FINALITY_DEPTH,
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
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;
        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
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

/// Regression test for EIP-161: touching empty accounts should not bloat state diff.
/// Currently this is expected to fail after the fix, since we assert the diff is larger.
struct TouchAccountsStateDiffTest;

#[async_trait]
impl TestCase for TouchAccountsStateDiffTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 1,
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

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        for _ in 0..10 {
            let _ = seq_test_client
                .send_eth(seq_test_client.from_addr, None, None, None, 0)
                .await?;
        }
        sequencer.client.send_publish_batch_request().await?;
        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        let proofs = wait_for_zkproofs(full_node, finalized_height, None, 1).await?;
        let proof1 = &proofs[0];

        for _ in 0..10 {
            let _ = seq_test_client
                .send_eth(Address::random(), None, None, None, 0)
                .await?;
        }
        sequencer.client.send_publish_batch_request().await?;

        da.wait_mempool_len(2, None).await?;

        // Finalize commitments.
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        let proofs = wait_for_zkproofs(full_node, finalized_height, None, 1).await?;
        let proof2 = &proofs[0];

        // Make sure touched empty account are not committed to state diff as per EIP-161
        assert_eq!(
            proof1
                .proof_output
                .state_diff
                .iter()
                .filter(|(k, _v)| k.starts_with(b"E/a"))
                .count(),
            proof2
                .proof_output
                .state_diff
                .iter()
                .filter(|(k, _v)| k.starts_with(b"E/a"))
                .count()
        );

        Ok(())
    }
}

#[tokio::test]
async fn touch_accounts_state_diff_test() -> Result<()> {
    TestCaseRunner::new(TouchAccountsStateDiffTest)
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
//         da.generate(DEFAULT_FINALITY_DEPTH).await?;

//         let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

//         for _ in 0..max_l2_blocks_per_commitment {
//             sequencer.client.send_publish_batch_request().await?;
//         }

//         // Wait for blob inscribe tx to be in mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(DEFAULT_FINALITY_DEPTH).await?;

//         let finalized_height = da.get_finalized_height(None).await?;
//         batch_prover
//             .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
//             .await?;

//         // Wait for batch proof tx to hit mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(DEFAULT_FINALITY_DEPTH).await?;
//         let _proofs = wait_for_zkproofs(full_node, finalized_height + DEFAULT_FINALITY_DEPTH, None, 1)
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

//         da.generate(DEFAULT_FINALITY_DEPTH).await?;
//         let finalized_height = da.get_finalized_height(None).await?;

//         batch_prover
//             .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
//             .await?;

//         // Wait for batch proof tx to hit mempool
//         da.wait_mempool_len(2, None).await?;

//         da.generate(DEFAULT_FINALITY_DEPTH).await?;
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

struct ParallelProvingTest;

#[async_trait]
impl TestCase for ParallelProvingTest {
    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![("PARALLEL_PROOF_LIMIT", "2")],
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
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait until batch prover processes the commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof txs to hit mempool
        da.wait_mempool_len(4, Some(Duration::from_secs(420)))
            .await?;

        // Write 2 batch proofs (4 txs) to a finalized DA block
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
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

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

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
        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

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

struct SubmitFakeProofRpcTest;

#[async_trait]
impl TestCase for SubmitFakeProofRpcTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 5,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            // prevent proving
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 170,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client = f.light_client_prover.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        // generate 1 commitment
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        sequencer.wait_for_l2_height(5, None).await.unwrap();
        batch_prover.wait_for_l2_height(5, None).await.unwrap();

        // wait for 1 commitment txs to hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // finalize 1 commitment
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();

        // ensure batch prover saw 1 commitment
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // prove commitment index 1 through rpc
        batch_prover
            .client
            .http_client()
            .prove(PartitionMode::Normal)
            .await
            .unwrap();

        // wait for 1 proof txs to hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // finalize 1 proof
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();
        // ensure light client processed the proof
        light_client
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // verify lcp output
        let lcp_output = light_client
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap()
            .light_client_proof_output;
        assert_eq!(lcp_output.last_sequencer_commitment_index.to::<u32>(), 1);
        assert_eq!(lcp_output.last_l2_height.to::<u32>(), 5);

        // generate 3 more commitments
        for _ in 0..max_l2_blocks_per_commitment * 3 {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        sequencer.wait_for_l2_height(20, None).await.unwrap();
        batch_prover.wait_for_l2_height(20, None).await.unwrap();

        // wait for 3 commitment txs to hit DA
        da.wait_mempool_len(6, None).await.unwrap();
        // finalize 3 commitments
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();
        // ensure batch prover saw 3 commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // first, submit index 4
        batch_prover
            .client
            .http_client()
            .submit_fake_proof(4, 4)
            .await
            .unwrap();

        // wait for 1 proof txs to hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // finalize 1 proof
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();
        // ensure light client processed the proof
        light_client
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // verify lcp output, last commitment index should not change due to gap
        let lcp_output = light_client
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap()
            .light_client_proof_output;
        assert_eq!(lcp_output.last_sequencer_commitment_index.to::<u32>(), 1);
        assert_eq!(lcp_output.last_l2_height.to::<u32>(), 5);

        // second, submit indices 2-3
        batch_prover
            .client
            .http_client()
            .submit_fake_proof(2, 3)
            .await
            .unwrap();

        // wait for 1 proof txs to hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // finalize 1 proof
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();
        // ensure light client processed the proof
        light_client
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // verify lcp output
        let lcp_output = light_client
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?
            .unwrap()
            .light_client_proof_output;
        assert_eq!(lcp_output.last_sequencer_commitment_index.to::<u32>(), 4);
        assert_eq!(lcp_output.last_l2_height.to::<u32>(), 20);

        // invoke prove so that commitment indices 2-3-4 gets dropped from pending pool
        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::Normal)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);
        // ensure the proof txs hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // write it to a block, we don't care about this proof
        da.generate(1).await.unwrap();

        // generate 1 last commitment
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await.unwrap();
        }
        sequencer.wait_for_l2_height(25, None).await.unwrap();
        batch_prover.wait_for_l2_height(25, None).await.unwrap();

        // wait for 1 commitment txs to hit DA
        da.wait_mempool_len(2, None).await.unwrap();
        // finalize 1 commitment
        da.generate(DEFAULT_FINALITY_DEPTH).await.unwrap();

        let finalized_height = da.get_finalized_height(None).await.unwrap();
        // ensure batch prover saw 1 commitment
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        // prove commitment index 5 through rpc
        let job_id = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::Normal)
            .await
            .unwrap()[0];
        let job_response = wait_for_prover_job(batch_prover, job_id, None)
            .await
            .unwrap();
        assert_eq!(job_response.commitments.len(), 1);
        assert_eq!(job_response.commitments[0].index.to::<u32>(), 5);
        let zkvm_prove_output = job_response.proof.unwrap().proof_output;

        // also submit fake proof of commitment index 5 through rpc
        let fake_proof_response = batch_prover
            .client
            .http_client()
            .submit_fake_proof(5, 5)
            .await
            .unwrap();
        // assert that fake proof response has null info field
        assert!(fake_proof_response.info.is_none());

        let native_prove_output = fake_proof_response.proof_output;
        // compare actual zkvm
        assert_eq!(zkvm_prove_output, native_prove_output);

        Ok(())
    }
}

#[tokio::test]
async fn test_batch_prover_submit_fake_proof_rpc() -> Result<()> {
    TestCaseRunner::new(SubmitFakeProofRpcTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
struct BatchProverCreateInputTest;

#[async_trait]
impl TestCase for BatchProverCreateInputTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        // Generate commitments to create input for proving
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for commitment transactions to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Finalize the commitments
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Ensure the batch prover sees the finalized commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Call batchProver_createInput to generate input for proving
        let inputs = batch_prover
            .client
            .http_client()
            .create_circuit_input(0, 1, PartitionMode::Normal)
            .await?;

        assert_eq!(inputs.len(), 1);

        let code_commitment = citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID;

        // Instantiate SP1Host
        let network = Network::Nightly;

        let sp1_config = SP1HostConfig::from_env().expect("Failed to load sp1 config");
        let mut sp1_host = SP1Host::new(network, sp1_config);

        for input in inputs {
            // Decode raw circuit input
            let raw_input = BASE64_STANDARD.decode(input).unwrap();

            // Add input to SP1Host
            sp1_host.add_hint(raw_input);

            // Run the proof generation
            let proof = sp1_host
                .run(
                    Uuid::new_v4(),
                    citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
                    citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID,
                    ReceiptType::Groth16,
                    false,
                )
                .await
                .expect("Proof generation failed")
                .await
                .expect("Proof channel should not close");

            let proof = proof.proof;
            let output: BatchProofCircuitOutput = SP1Host::extract_output(&proof).unwrap();

            // Verify the proof
            SP1Host::verify(proof.as_slice(), &code_commitment, true)
                .expect("Proof verification failed");

            assert_eq!(output.last_l2_height(), max_l2_blocks_per_commitment);
            assert_eq!(output.sequencer_commitment_index_range(), (1, 1));

            let commitment = sequencer
                .client
                .http_client()
                .get_sequencer_commitment_by_index(U32::from(1))
                .await?
                .unwrap();
            let l2_block = sequencer
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(commitment.l2_end_block_number))
                .await?
                .unwrap();
            let state_roots = output.state_roots().clone();
            assert_eq!(state_roots[1], l2_block.header.state_root);
        }

        // Test that non-existent commitment ranges are properly rejected
        let result = batch_prover
            .client
            .http_client()
            .create_circuit_input(100, 200, PartitionMode::Normal)
            .await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("No commitments found"),
            "Expected error about no commitments found, got: {}",
            error_msg
        );

        sequencer.wait_until_stopped().await?;
        batch_prover.wait_until_stopped().await?;

        Ok(())
    }
}

#[tokio::test]
async fn batch_prover_create_input_test() -> Result<()> {
    TestCaseRunner::new(BatchProverCreateInputTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Init code returning a runtime that calls `calldata[0..32]` (an address) with
/// `calldata[32..]`, then stores `n` in slot 0 and keccak256(returndata ‖ success) in
/// slot `n`, so every precompile result becomes part of the state root:
///
/// ```text
/// calldatacopy(0, 32, calldatasize - 32)
/// ok := call(gas, calldataload(0), 0, 0, calldatasize - 32, 0, 0)
/// returndatacopy(0, 0, returndatasize); mstore(returndatasize, ok)
/// n := sload(0) + 1; sstore(0, n); sstore(n, keccak256(0, returndatasize + 32))
/// ```
const PRECOMPILE_PROBE: &str = "6035600c60003960356000f3\
     602036038060206000376000600082600060006000355af190503d600060003e3d523d602001600020600054600101806000555500";
/// Enough for the most expensive vector, so no precompile fails for lack of gas.
const PRECOMPILE_PROBE_GAS: u64 = 2_000_000;

#[derive(Clone, Copy, Debug)]
enum PrecompileOutcome {
    Output,
    EmptyOutput,
    Error,
}

/// Edge-case inputs for every precompile, with their expected outcome on the node.
fn precompile_vectors() -> Vec<(&'static str, u16, Vec<u8>, PrecompileOutcome)> {
    use PrecompileOutcome::*;

    let h = |s: &str| hex::decode(s).unwrap();
    let word = |v: u64| U256::from(v).to_be_bytes::<32>().to_vec();
    let cat = |parts: &[&[u8]]| parts.concat();

    // ecrecover: a high-s signature, and its low-s counterpart.
    let secp_n = U256::from_be_slice(&h(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ));
    let hash = h("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c");
    let r = h("73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f");
    let s = h("eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549");
    let low_s = (secp_n - U256::from_be_slice(&s)).to_be_bytes::<32>();
    let ecrecover = cat(&[&hash, &word(28), &r, &s]);

    let modexp = |b: &[u8], e: &[u8], m: &[u8]| {
        cat(&[
            &word(b.len() as u64),
            &word(e.len() as u64),
            &word(m.len() as u64),
            b,
            e,
            m,
        ])
    };

    let bn_p = h("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
    let bn_r = h("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    let bn_g1 = cat(&[&word(1), &word(2)]);
    let bn_g1_neg = cat(&[
        &word(1),
        &h("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"),
    ]);
    let bn_off_curve = cat(&[&word(1), &word(3)]);
    let bn_g2 = h(
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
                   1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
                   090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
                   12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    );
    let mut bn_g2_off_curve = bn_g2.clone();
    *bn_g2_off_curve.last_mut().unwrap() ^= 1;

    // EIP-152 test vector 5 ("abc", 12 rounds, final block).
    let blake2f = |rounds: u32, last: u8| {
        cat(&[
            &rounds.to_be_bytes(),
            &h(
                "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
                d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
            ),
            &[b"abc".as_slice(), &[0u8; 125]].concat(),
            &h("03000000000000000000000000000000"),
            &[last],
        ])
    };

    let p256 = h(
        "b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955\
                  289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556\
                  d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da\
                  3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdc\
                  ef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1",
    );
    let mut p256_bad = p256.clone();
    p256_bad[40] ^= 1;
    // BIP-340 test vector 0.
    let schnorr = h(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\
                     0000000000000000000000000000000000000000000000000000000000000000\
                     e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215\
                     25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
    );
    let mut schnorr_bad = schnorr.clone();
    *schnorr_bad.last_mut().unwrap() ^= 1;

    let mut vectors = vec![
        ("ecrecover high-s", 0x01, ecrecover.clone(), Output),
        (
            "ecrecover low-s",
            0x01,
            cat(&[&hash, &word(27), &r, &low_s]),
            Output,
        ),
        (
            "ecrecover v=29",
            0x01,
            cat(&[&hash, &word(29), &r, &s]),
            EmptyOutput,
        ),
        (
            "ecrecover s=n",
            0x01,
            cat(&[&hash, &word(28), &r, &secp_n.to_be_bytes::<32>()]),
            EmptyOutput,
        ),
        (
            "ecrecover r=0",
            0x01,
            cat(&[&hash, &word(28), &word(0), &s]),
            EmptyOutput,
        ),
        (
            "ecrecover truncated",
            0x01,
            ecrecover[..64].to_vec(),
            EmptyOutput,
        ),
        ("sha256 empty", 0x02, vec![], Output),
        ("sha256 55 bytes", 0x02, vec![0xab; 55], Output),
        ("sha256 64 bytes", 0x02, vec![0xab; 64], Output),
        ("sha256 1000 bytes", 0x02, vec![0xab; 1000], Output),
        ("ripemd160 empty", 0x03, vec![], Output),
        ("ripemd160 1000 bytes", 0x03, vec![0xab; 1000], Output),
        ("identity empty", 0x04, vec![], EmptyOutput),
        ("identity 100 bytes", 0x04, vec![0xab; 100], Output),
        (
            "modexp eip-198",
            0x05,
            modexp(
                &[3],
                &h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"),
                &h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
            ),
            Output,
        ),
        (
            "modexp empty modulus",
            0x05,
            modexp(&[3], &[5], &[]),
            EmptyOutput,
        ),
        (
            "modexp zero modulus",
            0x05,
            modexp(&[3], &[5], &[0]),
            Output,
        ),
        (
            "modexp even modulus",
            0x05,
            modexp(&[0xff; 32], &[0xfe; 32], &h("010000000000000000")),
            Output,
        ),
        (
            "modexp zero exponent",
            0x05,
            modexp(&[7], &[], &[13]),
            Output,
        ),
        (
            "modexp base above modulus",
            0x05,
            modexp(&[0xff; 64], &[3], &[1, 0, 1]),
            Output,
        ),
        ("bn254 add", 0x06, cat(&[&bn_g1, &bn_g1]), Output),
        (
            "bn254 add infinity",
            0x06,
            cat(&[&[0u8; 64], &bn_g1]),
            Output,
        ),
        (
            "bn254 add off-curve",
            0x06,
            cat(&[&bn_off_curve, &bn_g1]),
            Error,
        ),
        (
            "bn254 add x=p",
            0x06,
            cat(&[&bn_p, &word(2), &bn_g1]),
            Error,
        ),
        ("bn254 mul", 0x07, cat(&[&bn_g1, &word(2)]), Output),
        ("bn254 mul by order", 0x07, cat(&[&bn_g1, &bn_r]), Output),
        (
            "bn254 mul off-curve",
            0x07,
            cat(&[&bn_off_curve, &word(2)]),
            Error,
        ),
        ("bn254 pairing empty", 0x08, vec![], Output),
        (
            "bn254 pairing",
            0x08,
            cat(&[&bn_g1, &bn_g2, &bn_g1_neg, &bn_g2]),
            Output,
        ),
        (
            "bn254 pairing bad length",
            0x08,
            cat(&[&bn_g1, &bn_g2])[..191].to_vec(),
            Error,
        ),
        (
            "bn254 pairing off-curve g2",
            0x08,
            cat(&[&bn_g1, &bn_g2_off_curve]),
            Error,
        ),
        ("blake2f", 0x09, blake2f(12, 1), Output),
        ("blake2f zero rounds", 0x09, blake2f(0, 1), Output),
        ("blake2f bad final flag", 0x09, blake2f(12, 2), Error),
        // Not a precompile on Citrea: a call to an empty account.
        ("kzg point evaluation", 0x0a, vec![0; 192], EmptyOutput),
        ("p256verify", 0x100, p256.clone(), Output),
        ("p256verify bad signature", 0x100, p256_bad, EmptyOutput),
        ("p256verify short", 0x100, p256[..159].to_vec(), EmptyOutput),
        ("schnorr verify", 0x200, schnorr.clone(), Output),
        (
            "schnorr verify bad signature",
            0x200,
            schnorr_bad,
            EmptyOutput,
        ),
        (
            "schnorr verify short",
            0x200,
            schnorr[..127].to_vec(),
            EmptyOutput,
        ),
    ];
    // EIP-2537 (BLS12-381) is not enabled on Citrea either.
    vectors.extend((0x0b..=0x11).map(|address| ("bls12-381", address, vec![0; 256], EmptyOutput)));
    vectors
}

/// Executes edge-case precompile calls on L2 and requires the batch guest, which runs
/// the SP1-patched (or unaccelerated) crypto, to reproduce the node's state roots.
struct PrecompileGuestParityTest;

#[async_trait]
impl TestCase for PrecompileGuestParityTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            proof_sampling_number: 999_999_999_999,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        use alloy::rpc::types::eth::TransactionRequest;

        use crate::common::client::MAX_FEE_PER_GAS;

        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();
        let client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;
        let precompile = |address: u16| {
            let mut bytes = [0u8; 20];
            bytes[18..].copy_from_slice(&address.to_be_bytes());
            Address::from(bytes)
        };

        let vectors = precompile_vectors();
        for (name, address, input, expected) in &vectors {
            let request = TransactionRequest::default()
                .from(client.from_addr)
                .to(precompile(*address))
                .input(input.clone().into())
                .gas_limit(PRECOMPILE_PROBE_GAS);
            let result = client.client.call(request).await;
            let matches = match (expected, &result) {
                (PrecompileOutcome::Output, Ok(output)) => !output.is_empty(),
                (PrecompileOutcome::EmptyOutput, Ok(output)) => output.is_empty(),
                (PrecompileOutcome::Error, Err(_)) => true,
                _ => false,
            };
            assert!(matches, "{name}: expected {expected:?}, got {result:?}");
        }

        let nonce = client
            .eth_get_transaction_count(client.from_addr, None)
            .await
            .unwrap();
        let _ = client
            .deploy_contract(hex::decode(PRECOMPILE_PROBE)?, Some(nonce))
            .await
            .unwrap();
        sequencer.client.send_publish_batch_request().await?;
        let probe = client.from_addr.create(nonce);

        // Stay below the mempool's per-account limit, one block per chunk.
        let blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        let mut blocks = 1;
        let mut tx_nonce = nonce + 1;
        for chunk in vectors.chunks(10) {
            for (_, address, input, _) in chunk {
                let data = [[0u8; 12].as_slice(), precompile(*address).as_slice(), input].concat();
                let request = TransactionRequest::default()
                    .from(client.from_addr)
                    .to(probe)
                    .input(data.into())
                    .gas_limit(PRECOMPILE_PROBE_GAS)
                    .nonce(tx_nonce)
                    .max_priority_fee_per_gas(10)
                    .max_fee_per_gas(MAX_FEE_PER_GAS);
                let _ = client.client.send_transaction(request).await?;
                tx_nonce += 1;
            }
            sequencer.client.send_publish_batch_request().await?;
            blocks += 1;
            sequencer.wait_for_l2_height(blocks, None).await?;
        }
        let calls = client
            .eth_get_storage_at(probe, U256::ZERO, None)
            .await
            .unwrap();
        assert_eq!(
            calls,
            U256::from(vectors.len()),
            "probe calls were not included"
        );

        // Complete a single commitment.
        assert!(blocks <= blocks_per_commitment);
        while blocks < blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
            blocks += 1;
        }
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        batch_prover
            .wait_for_l1_height(da.get_finalized_height(None).await?, None)
            .await?;

        let inputs = batch_prover
            .client
            .http_client()
            .create_circuit_input(0, 1, PartitionMode::Normal)
            .await?;
        assert_eq!(inputs.len(), 1);
        let mut host = SP1Host::new(Network::Nightly, SP1HostConfig::from_env()?);
        host.add_hint(BASE64_STANDARD.decode(&inputs[0])?);
        let proof = host
            .run(
                Uuid::new_v4(),
                citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ELF.to_vec(),
                citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID,
                ReceiptType::Groth16,
                false,
            )
            .await?
            .await?
            .proof;
        let output: BatchProofCircuitOutput = SP1Host::extract_output(&proof)?;
        assert_eq!(output.sequencer_commitment_index_range(), (1, 1));

        let l2_block = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(output.last_l2_height()))
            .await?
            .unwrap();
        assert_eq!(output.state_roots()[1], l2_block.header.state_root);

        Ok(())
    }
}

#[tokio::test]
async fn test_precompile_edge_cases_match_in_guest() -> Result<()> {
    TestCaseRunner::new(PrecompileGuestParityTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct InvokeCachePruningTest;

#[async_trait]
impl TestCase for InvokeCachePruningTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 55,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 1_000_000,
                pending_tx_size: 100_000_000,
                queue_tx_limit: 1_000_000,
                queue_tx_size: 100_000_000,
                base_fee_tx_limit: 1_000_000,
                base_fee_tx_size: 100_000_000,
                max_account_slots: 1_000_000,
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
        let sequencer = f.sequencer.as_mut().unwrap();
        let batch_prover = f.batch_prover.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        let signed_txs = self.create_deploy_transactions().await;
        for signed_tx in signed_txs {
            sequencer
                .client
                .http_client()
                .eth_send_raw_transaction(signed_tx.into())
                .await
                .unwrap();
        }

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        // we publish 55 blocks - this should hit the state diff limit
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await
            .unwrap();

        // Wait for commitment transactions to hit the mempool
        da.wait_mempool_len(2, None).await?;

        // Finalize the commitments
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Ensure the batch prover sees the finalized commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof transactions to hit the mempool
        // In this proof, cache limit of 6MB will be hit and pruning will occur.
        // If the proving session ended successfully, we are gucci
        da.wait_mempool_len(2, Some(Duration::from_secs(300)))
            .await?;

        // Finalize the zk proof
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for full node to see and process zk proof
        full_node
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        let last_proven_l2_data = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(last_proven_l2_data.commitment_index, 1);
        // Should be exactly 55 blocks in the commitment
        assert_eq!(last_proven_l2_data.height, 55);

        Ok(())
    }
}

impl InvokeCachePruningTest {
    async fn create_deploy_transactions(&self) -> Vec<Vec<u8>> {
        // 11 tx fits into a single block
        const DEPLOY_COUNT: usize = 55 * 11;

        let bytecode_hex = fs::read_to_string("tests/bitcoin/test-data/big-contract.bin").unwrap();
        let bytecode_size = bytecode_hex.len() / 2;

        // extra 32 bytes for constructor argument
        let mut bytecode_with_args = vec![0; bytecode_size + 32];
        hex::decode_to_slice(bytecode_hex, &mut bytecode_with_args[0..bytecode_size]).unwrap();

        // prepare signer
        let private_key: [u8; 32] =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap()
                .try_into()
                .unwrap();
        let mut signer = PrivateKeySigner::from_slice(&private_key).unwrap();
        signer.set_chain_id(Some(5655));

        let mut signed_txs = Vec::with_capacity(DEPLOY_COUNT);
        for i in 0..DEPLOY_COUNT {
            // set constructor argument different for each contract.
            // since constructor argument sets immutable storage variable
            // this will make bytecode of each contract different
            bytecode_with_args[bytecode_size..]
                .copy_from_slice(U256::from(i).to_be_bytes::<32>().as_slice());

            let mut tx = TxLegacy {
                chain_id: Some(5655),
                nonce: i as u64,
                gas_price: 1_000_000_000 * 1_000_000_000, // 1_000_000_000 gwei
                gas_limit: 3_000_000,                     // 3 million gas
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::copy_from_slice(&bytecode_with_args),
            };

            let signature = signer.sign_transaction(&mut tx).await.unwrap();
            let signed_tx = tx.into_signed(signature);

            let mut rlp_buf = Vec::with_capacity(signed_tx.rlp_encoded_length());
            signed_tx.rlp_encode(&mut rlp_buf);

            signed_txs.push(rlp_buf);
        }

        signed_txs
    }
}

#[tokio::test]
async fn invoke_cache_prune_test() -> Result<()> {
    TestCaseRunner::new(InvokeCachePruningTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct RetryProvingTest;

#[async_trait]
impl TestCase for RetryProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
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

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment * 4 {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(8, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        let proving_job = batch_prover
            .client
            .http_client()
            .get_proving_job_of_commitment(1, Some(true))
            .await?
            .unwrap();
        assert_eq!(proving_job.commitments.len(), 4);

        // retry proving the same job
        let new_job_id = batch_prover
            .client
            .http_client()
            .retry_proving_job(proving_job.id)
            .await?;
        assert_ne!(new_job_id, proving_job.id, "new job id should be different");

        // check the commitments of the new proving job
        let new_proving_job = wait_for_prover_job(batch_prover, new_job_id, None).await?;
        assert_eq!(new_proving_job.commitments.len(), 4);

        // check the mapping from commitment to proving job is updated
        let job_from_commitment = batch_prover
            .client
            .http_client()
            .get_proving_job_of_commitment(1, Some(true))
            .await?
            .unwrap();
        assert_eq!(job_from_commitment.id, new_job_id);

        Ok(())
    }
}

#[tokio::test]
async fn retry_proving_test() -> Result<()> {
    TestCaseRunner::new(RetryProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct ProvingSessionInfoTest;

#[async_trait]
impl TestCase for ProvingSessionInfoTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
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

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // check with_proof=false
        let empty_proof = batch_prover
            .client
            .http_client()
            .get_proving_job_of_commitment(1, Some(false))
            .await?
            .expect("proving job should exist");
        assert!(empty_proof.proof.is_none(), "proof should not be here");

        // Check RPC default with_proof=true for getting proving job by commitment
        let with_proof_default = batch_prover
            .client
            .http_client()
            .get_proving_job_of_commitment(1, None) // by default with_proof=true
            .await?
            .unwrap();
        assert!(with_proof_default.proof.is_some(), "proof should exist");

        let proving_job = batch_prover
            .client
            .http_client()
            .get_proving_job_of_commitment(1, Some(true))
            .await?
            .expect("proving job should exist");
        assert_eq!(proving_job.commitments.len(), 1);

        let proving_info = proving_job.proof.expect("proof should exist").info;
        let Some(ProvingSessionInfo::LocalExecution(stats)) = proving_info else {
            panic!("unexpected proving info type");
        };

        assert!(stats.instruction_count > 0);
        assert!(stats.syscall_count > 0);
        assert!(stats.gas > 0);
        Ok(())
    }
}

#[tokio::test]
async fn proving_session_info_test() -> Result<()> {
    TestCaseRunner::new(ProvingSessionInfoTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
