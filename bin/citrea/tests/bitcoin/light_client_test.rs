use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{U32, U64};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use citrea_batch_prover::rpc::BatchProverRpcClient;
use citrea_batch_prover::PartitionMode;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, CitreaMode, LightClientProverConfig, SequencerConfig,
    SequencerMempoolConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_fullnode::rpc::FullNodeRpcClient;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use rand::{thread_rng, Rng};
use reth_tasks::TaskManager;
use risc0_zkvm::{FakeReceipt, InnerReceipt, MaybePruned, ReceiptClaim};
use sov_rollup_interface::da::{BatchProofMethodId, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::BatchProofMethodIdRpcResponse;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};

use super::batch_prover_test::wait_for_zkproofs;
use super::get_citrea_path;
use crate::bitcoin::batch_prover_test::wait_for_prover_job;
use crate::bitcoin::utils::{spawn_bitcoin_da_service, DaServiceKeyKind};

pub const TEN_MINS: Duration = Duration::from_secs(10 * 60);

struct LightClientProvingTest {}

#[async_trait]
impl TestCase for LightClientProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 5,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        assert!(lcp.is_some());

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to see zkproofs
        let batch_proof = wait_for_zkproofs(
            full_node,
            finalized_height,
            Some(Duration::from_secs(7200)),
            1,
        )
        .await
        .unwrap();

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proof[0].proof_output.final_state_root()
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTest {})
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LightClientProvingTestMultipleProofs;

#[async_trait]
impl TestCase for LightClientProvingTestMultipleProofs {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 50,
            da_update_interval_ms: 500,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_size: 2000,
                max_account_slots: 2600,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            proof_sampling_number: 99999999,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(169)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let n_commitments = 2;

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..n_commitments * max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(n_commitments * max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment txs to be submitted to DA
        da.wait_mempool_len((n_commitments * 2) as usize, Some(TEN_MINS))
            .await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to see commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, None)
            .await
            .unwrap();

        // There are two commitments, for each commitment generate a proof
        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::OneByOne)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 2);

        // Wait for both prover jobs to finish
        let response_1 = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        let response_2 = wait_for_prover_job(batch_prover, job_ids[1], None)
            .await
            .unwrap();
        assert_eq!(response_1.commitments.len(), 1);
        assert_eq!(response_2.commitments.len(), 1);

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None, 2).await?;
        assert_eq!(batch_proofs.len(), 2);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await
            .unwrap();
        assert!(lcp.is_some());

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proofs[(n_commitments - 1) as usize]
                .proof_output
                .final_state_root()
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

        // Generate another da block so we generate another lcp
        da.generate(1).await?;

        let last_finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(last_finalized_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp2 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(last_finalized_height)
            .await
            .unwrap();
        assert!(lcp2.is_some());

        // Since there are no batch proofs the state root should be the same as the last one
        let light_client_proof2 = lcp2.unwrap();
        assert_eq!(
            light_client_proof2.light_client_proof_output.l2_state_root,
            light_client_proof.light_client_proof_output.l2_state_root
        );

        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );
        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2
                .light_client_proof_output
                .last_sequencer_commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof2
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof2
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

        // Let's generate a new batch proof
        // publish max_l2_blocks_per_commitment confirmations
        let l2_height = sequencer.client.ledger_get_head_l2_block_height().await?;
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(l2_height + max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await?;

        // There is one commitment, generate a single proof
        let job_ids = batch_prover
            .client
            .http_client()
            .prove(PartitionMode::OneByOne)
            .await
            .unwrap();

        let response = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        assert_eq!(response.commitments.len(), 1);

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(full_node, batch_proof_l1_height, None, 1).await?;
        assert_eq!(batch_proofs.len(), 1);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp3 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await
            .unwrap();
        assert!(lcp3.is_some());

        let light_client_proof3 = lcp3.unwrap();
        assert_eq!(
            light_client_proof3
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proofs[0].proof_output.final_state_root()
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );
        assert_ne!(
            light_client_proof3
                .light_client_proof_output
                .last_sequencer_commitment_index,
            light_client_proof
                .light_client_proof_output
                .last_sequencer_commitment_index
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.l2_state_root,
            light_client_proof.light_client_proof_output.l2_state_root
        );

        let proven_height = full_node
            .client
            .http_client()
            .get_last_proven_l2_height()
            .await?
            .unwrap();
        assert_eq!(
            proven_height.height,
            light_client_proof3
                .light_client_proof_output
                .last_l2_height
                .to::<u64>()
        );
        assert_eq!(
            proven_height.commitment_index,
            light_client_proof3
                .light_client_proof_output
                .last_sequencer_commitment_index
                .to::<u32>()
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving_multiple_proofs() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTestMultipleProofs)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LightClientBatchProofMethodIdUpdateTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for LightClientBatchProofMethodIdUpdateTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 2,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                "79122E48DF1A002FB6584B2E94D0D50F95037416C82DAF280F21CD67D17D9077".to_string(),
            ),
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        // publish max_l2_blocks_per_commitment confirmations
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the commitment tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let commitment_l1_height = da.get_finalized_height(None).await?;

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_commitment_indices_by_l1(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let _lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let batch_proof_method_ids_before = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Verify the current batch proof method ids
        assert_eq!(
            batch_proof_method_ids_before,
            vec![BatchProofMethodIdRpcResponse {
                height: U64::from(0),
                method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
            }],
        );

        // Send BatchProofMethodId transaction to da
        let new_batch_proof_method_id = [1u32; 8];
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::BatchProofMethodId(BatchProofMethodId {
                    method_id: new_batch_proof_method_id,
                    activation_l2_height: 210,
                }),
                1,
            )
            .await
            .unwrap();

        // Ensure that method id tx is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the method id tx
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let method_id_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process method id update
        light_client_prover
            .wait_for_l1_height(method_id_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that 1 l1 block before method id tx, still has the same batch proof method ids
        let _lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(method_id_l1_height - 1)
            .await?;

        // Assert that method ids are updated
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        // Verify the current batch proof method ids
        assert_eq!(
            batch_proof_method_ids,
            vec![
                BatchProofMethodIdRpcResponse {
                    height: U64::from(0),
                    method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id.into()
                }
            ]
        );

        // Generate one more empty l1 block
        da.generate(1).await?;

        // Wait for light client to process it
        light_client_prover
            .wait_for_l1_height(method_id_l1_height + 1, None)
            .await
            .unwrap();

        // Verify that previously updated method ids are being used
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        assert_eq!(
            batch_proof_method_ids,
            vec![
                BatchProofMethodIdRpcResponse {
                    height: U64::from(0),
                    method_id: citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID.into()
                },
                BatchProofMethodIdRpcResponse {
                    height: U64::from(210),
                    method_id: new_batch_proof_method_id.into()
                }
            ]
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_batch_proof_method_id_update() -> Result<()> {
    TestCaseRunner::new(LightClientBatchProofMethodIdUpdateTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct LightClientUnverifiableBatchProofTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for LightClientUnverifiableBatchProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        // Get initial method ids and genesis state root
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(batch_proof_method_ids.len() == 1);

        let fork2_height: u64 = batch_proof_method_ids[0].height.to();
        let l1_hash = da.get_block_hash(finalized_height).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: fork2_height + 1,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: fork2_height * 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_2.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: fork2_height * 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_3.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment_4 = SequencerCommitment {
            merkle_root: [4u8; 32],
            index: 4,
            l2_end_block_number: fork2_height * 4,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment_4.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(8, None).await?;

        // Finalize the DA block which contains the seq comm txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            fork2_height + 1,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            fork2_height * 3,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_3.clone()],
            Some(fake_sequencer_commitment_2.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        // Expect unparsable journal to be skipped
        let unparsable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            fork2_height * 4,
            batch_proof_method_ids[0].method_id.into(),
            None,
            true,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_4.clone()],
            Some(fake_sequencer_commitment_3.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unparsable_batch_proof), 1)
            .await
            .unwrap();

        let verifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            fork2_height * 2,
            batch_proof_method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_batch_proof), 1)
            .await
            .unwrap();

        // Give it a random method id to make it unverifiable
        let random_method_id = [1u32; 8];
        let unverifiable_batch_proof = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            fork2_height * 4,
            random_method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment_4.clone()],
            Some(fake_sequencer_commitment_3.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unverifiable_batch_proof), 1)
            .await
            .unwrap();

        // Ensure that all four batch proofs is submitted to DA
        da.wait_mempool_len(10, None).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process unverifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof without panic but it should not have updated the state root
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The unverifiable batch proof and malformed journal batch proof should not have updated the state root or the last l2 height
        assert_eq!(lcp_output.l2_state_root, [3u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(fork2_height * 3));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(3));

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_unverifiable_batch_proof() -> Result<()> {
    TestCaseRunner::new(LightClientUnverifiableBatchProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct VerifyChunkedTxsInLightClient {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for VerifyChunkedTxsInLightClient {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let proof_last_l2_height: u64 = 10;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: proof_last_l2_height,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: proof_last_l2_height * 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: proof_last_l2_height * 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(6, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        // Get initial method ids and genesis state root
        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(batch_proof_method_ids.len() == 1);

        // Even though the state diff is 100kb the proof will be 200kb because the fake receipt claim also has the journal
        // But the compressed size will go down to 100kb
        let state_diff_100kb = create_random_state_diff(100);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 100kb (compressed size) batch proof (not 1mb because if testing feature is enabled max body size is 39700), this batch proof will consist of 3 chunk and 1 aggregate transactions because 100kb/40kb = 3 chunks
        let verifiable_100kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            proof_last_l2_height,
            batch_proof_method_ids[0].method_id.into(),
            Some(state_diff_100kb.clone()),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_100kb_batch_proof), 1)
            .await
            .unwrap();

        // In total 3 chunks 1 aggregate with all of them having reveal and commit txs we should have 8 txs in mempool
        da.wait_mempool_len(8, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now generate another proof but this time:
        // Have 4 chunks and 1 aggregate
        // First two chunks will should be in block n
        // Last two chunks should be in block n+1
        // And the aggregate should be in block n+2
        // After the block n+2 is processed we should see the state root updated
        let state_diff_130kb = create_random_state_diff(130);

        let finalized_height = da.get_finalized_height(None).await?;
        // finalized_height - 3 does not serve any purpose beyond just trying a different number
        // it could be finalized_height or finalized_height - x (x any number)
        let l1_hash = da.get_block_hash(finalized_height - 3).await?;

        let verifiable_130kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            proof_last_l2_height * 2,
            batch_proof_method_ids[0].method_id.into(),
            Some(state_diff_130kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(verifiable_130kb_batch_proof), 1)
            .await
            .unwrap();

        // In total 4 chunks 1 aggregate with all of them having reveal and commit txs we should have 10 txs in mempool
        da.wait_mempool_len(10, Some(TEN_MINS)).await?;

        // Get txs from mempool
        let txs = da.get_raw_mempool().await?;

        // // Get the first four txs ( first two chunks )
        let first_two_chunks = txs[0..4]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();
        let last_two_chunks = txs[4..8]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();
        let aggregate = txs[8..10]
            .iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();

        let addr = da
            .get_new_address(None, None)
            .await?
            .assume_checked()
            .to_string();

        da.generate_block(addr.clone(), first_two_chunks).await?;
        // First two chunks should be in block n
        da.wait_mempool_len(6, Some(TEN_MINS)).await?;

        da.generate_block(addr.clone(), last_two_chunks).await?;
        // Last two chunks should be in block n+1
        da.wait_mempool_len(2, Some(TEN_MINS)).await?;

        da.generate_block(addr.clone(), aggregate).await?;
        // Aggregate should be in block n+2
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        // Finalize the DA block which contains the aggregate txs
        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp_first_chunks = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height - 2)
            .await?;

        let lcp_output = lcp_first_chunks.unwrap().light_client_proof_output;

        // The batch proof should not have updated the state root and the last l2 height because these are only the chunks
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        let lcp_last_chunks = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height - 1)
            .await?;

        let lcp_output = lcp_last_chunks.unwrap().light_client_proof_output;

        // The batch proof should not have updated the state root and the last l2 height because these are only the chunks
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(proof_last_l2_height));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Expect light client prover to have generated light client proof
        let lcp_aggregate = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp_aggregate.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(proof_last_l2_height * 2)
        );
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        let random_method_id = [1u32; 8];

        // This should result in 3 chunks and 1 aggregate tx
        let unverifiable_100kb_batch_proof = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            proof_last_l2_height * 3,
            random_method_id,
            Some(state_diff_100kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment3],
            Some(fake_sequencer_commitment2.serialize_and_calculate_sha_256()),
        );
        let _ = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(unverifiable_100kb_batch_proof), 1)
            .await
            .unwrap();

        // In total 3 chunks 1 aggregate with all of them having reveal and commit txs we should have 8 txs in mempool
        da.wait_mempool_len(8, Some(TEN_MINS)).await?;

        // Finalize the DA block which contains the batch proof txs
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should NOT have updated the state root and the last l2 height
        // Because it is not verified
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(
            lcp_output.last_l2_height,
            U64::from(proof_last_l2_height * 2)
        );
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        Ok(())
    }
}

#[tokio::test]
async fn test_verify_chunked_txs_in_light_client() -> Result<()> {
    TestCaseRunner::new(VerifyChunkedTxsInLightClient {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct UnchainedBatchProofsTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnchainedBatchProofsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 164,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 200,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: 300,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment4 = SequencerCommitment {
            merkle_root: [4u8; 32],
            index: 4,
            l2_end_block_number: 400,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment4.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(8, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(170)
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let l1_hash = da.get_block_hash(171).await?;

        // put 3 bp in a block
        // first one is chained, second one is unchained, third one can be chained to the second one
        // on the next block, we put another bp that can be chained to the first one in the previous block
        // and the second-third will chain to this one

        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let bp2 = create_serialized_fake_receipt_batch_proof(
            [2u8; 32],
            300,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment3.clone()],
            Some(fake_sequencer_commitment2.serialize_and_calculate_sha_256()),
        );

        let bp3 = create_serialized_fake_receipt_batch_proof(
            [3u8; 32],
            400,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment4.clone()],
            Some(fake_sequencer_commitment3.serialize_and_calculate_sha_256()),
        );

        let bp4 = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            200,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        let mut txids = bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1)
            .await
            .unwrap();

        txids.extend(
            bitcoin_da_service
                .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2), 1)
                .await
                .unwrap(),
        );

        txids.extend(
            bitcoin_da_service
                .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp3), 1)
                .await
                .unwrap(),
        );
        da.wait_mempool_len(6, None).await?;

        da.generate_block(
            da.get_new_address(None, None)
                .await?
                .assume_checked()
                .to_string(),
            txids.into_iter().map(|txid| txid.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp4), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + 2 * DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(start_l1_height + 2 * DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        assert_eq!(lcp_output.l2_state_root, [4u8; 32]);
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(4));

        Ok(())
    }
}

#[tokio::test]
async fn test_unchained_batch_proofs_in_light_client() -> Result<()> {
    TestCaseRunner::new(UnchainedBatchProofsTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct UnknownL1HashBatchProofTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for UnknownL1HashBatchProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 165,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;
        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();
        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(170)
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let mut l1_hash = da.get_block_hash(171).await?.to_raw_hash().to_byte_array();

        // make it uknown
        l1_hash[0] = l1_hash[0].wrapping_add(1);

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash,
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // batch proof with unknown L1 hash was ignored
        assert_eq!(lcp_output.l2_state_root, genesis_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        Ok(())
    }
}

#[tokio::test]
async fn test_unknown_l1_hash_batch_proof_in_light_client() -> Result<()> {
    TestCaseRunner::new(UnknownL1HashBatchProofTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ChainProofByCommitmentIndex {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ChainProofByCommitmentIndex {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 100 * 2,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        let fake_sequencer_commitment3 = SequencerCommitment {
            merkle_root: [3u8; 32],
            index: 3,
            l2_end_block_number: 100 * 3,
        };

        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment3.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(6, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        // Get initial method ids and genesis state root
        let method_ids = batch_proof_method_ids;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(method_ids.len() == 1);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            200,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![
                fake_sequencer_commitment.clone(),
                fake_sequencer_commitment2.clone(),
            ],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1)
            .await
            .unwrap();

        let bp = create_serialized_fake_receipt_batch_proof(
            fake_sequencer_commitment.merkle_root, // using the roots as state roots in this test
            300,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![
                fake_sequencer_commitment2.clone(),
                fake_sequencer_commitment3.clone(),
            ],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1)
            .await
            .unwrap();

        da.wait_mempool_len(4, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, [3u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(300));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(3));

        Ok(())
    }
}

#[tokio::test]
async fn test_chain_proof_by_commitment_index() -> Result<()> {
    TestCaseRunner::new(ChainProofByCommitmentIndex {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProofWithMissingCommitment {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ProofWithMissingCommitment {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 171,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to create light client proof.
        light_client_prover
            .wait_for_l1_height(finalized_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        // Get initial method ids and genesis state root
        let method_ids = batch_proof_method_ids;
        let genesis_state_root = lcp_output.l2_state_root;

        assert!(method_ids.len() == 1);

        let l1_hash = da.get_block_hash(finalized_height).await?;

        let bp = create_serialized_fake_receipt_batch_proof(
            genesis_state_root,
            100,
            method_ids[0].method_id.into(),
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Make sure all of them are in the block
        let mempool = da.get_raw_mempool().await?;
        assert!(mempool.is_empty());

        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Wait for light client prover to process verifiable batch proof
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;

        let lcp_output = lcp.unwrap().light_client_proof_output;

        // The batch proof should have updated the state root and the last l2 height
        assert_eq!(lcp_output.l2_state_root, genesis_state_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        Ok(())
    }
}

#[tokio::test]
async fn test_proof_with_missing_commitment_is_discarded() -> Result<()> {
    TestCaseRunner::new(ProofWithMissingCommitment {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

struct ProofAndCommitmentWithWrongDaPubkey {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for ProofAndCommitmentWithWrongDaPubkey {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            initial_da_height: 164,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 10000,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        let batch_prover_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::BatchProver,
        )
        .await;

        let sequencer_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Sequencer,
        )
        .await;

        let malicious_bitcoin_da_service = spawn_bitcoin_da_service(
            self.task_manager.executor(),
            &da.config,
            Self::test_config().dir,
            DaServiceKeyKind::Other(
                "1212121212121212121212121212121212121212121212121212121212121212".to_string(),
            ),
        )
        .await;

        let fake_sequencer_commitment = SequencerCommitment {
            merkle_root: [1u8; 32],
            index: 1,
            l2_end_block_number: 100,
        };

        let _ = malicious_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let start_l1_height = da.get_finalized_height(None).await?;

        light_client_prover.wait_for_l1_height(170, None).await?;

        let initial_lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(170)
            .await?
            .unwrap();

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;

        let method_id = batch_proof_method_ids[0].method_id.into();
        let genesis_root = initial_lcp.light_client_proof_output.l2_state_root;
        let l1_hash = da.get_block_hash(171).await?;

        // put 1 bp in a block with wrong commitment da pub key, this proof should not transition because we should not have the commitment
        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let txids = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate_block(
            da.get_new_address(None, None)
                .await?
                .assume_checked()
                .to_string(),
            txids.into_iter().map(|txid| txid.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        light_client_prover
            .wait_for_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(start_l1_height + DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should not have transitioned because the commitment should not have made it in.
        assert_eq!(lcp_output.l2_state_root, genesis_root);
        assert_eq!(lcp_output.last_l2_height, U64::from(0));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(0));

        // Now send with the correct da service
        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // put 1 bp in a block with wrong commitment da pub key, this proof should not transition because we should not have the commitment
        let bp1 = create_serialized_fake_receipt_batch_proof(
            genesis_root,
            100,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment.clone()],
            None,
        );

        let txids = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp1), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate_block(
            da.get_new_address(None, None)
                .await?
                .assume_checked()
                .to_string(),
            txids.into_iter().map(|txid| txid.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should have transitioned because the commitment now has the correct da pub key.
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now send batch proof with wrong da pub key and expect it to not transition
        let fake_sequencer_commitment2 = SequencerCommitment {
            merkle_root: [2u8; 32],
            index: 2,
            l2_end_block_number: 200,
        };

        // Now send with the correct da service
        let _ = sequencer_bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(fake_sequencer_commitment2.clone()),
                1,
            )
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // put 1 bp in a block with wrong batch prover da pub key, this proof should not transition because it should not be accepted
        let bp2 = create_serialized_fake_receipt_batch_proof(
            [1u8; 32],
            200,
            method_id,
            None,
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![fake_sequencer_commitment2.clone()],
            Some(fake_sequencer_commitment.serialize_and_calculate_sha_256()),
        );

        let txids = malicious_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2.clone()), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate_block(
            da.get_new_address(None, None)
                .await?
                .assume_checked()
                .to_string(),
            txids.into_iter().map(|txid| txid.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should not have transitioned because the commitment should not have made it in.
        assert_eq!(lcp_output.l2_state_root, [1u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(100));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(1));

        // Now send batch proof with the correct da pub key and expect it to transition
        let txids = batch_prover_bitcoin_da_service
            .send_transaction_with_fee_rate(DaTxRequest::ZKProof(bp2.clone()), 1)
            .await
            .unwrap();

        da.wait_mempool_len(2, None).await?;

        da.generate_block(
            da.get_new_address(None, None)
                .await?
                .assume_checked()
                .to_string(),
            txids.into_iter().map(|txid| txid.to_string()).collect(),
        )
        .await?;

        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height)
            .await?
            .unwrap();

        let lcp_output = lcp.light_client_proof_output;

        // Should have transitioned because the proof should have made it in.
        assert_eq!(lcp_output.l2_state_root, [2u8; 32]);
        assert_eq!(lcp_output.last_l2_height, U64::from(200));
        assert_eq!(lcp_output.last_sequencer_commitment_index, U32::from(2));

        Ok(())
    }
}

#[tokio::test]
async fn test_proof_and_commitment_with_wrong_da_pubkey() -> Result<()> {
    TestCaseRunner::new(ProofAndCommitmentWithWrongDaPubkey {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}

pub(crate) fn create_random_state_diff(size_in_kb: u64) -> BTreeMap<Arc<[u8]>, Option<Arc<[u8]>>> {
    let mut rng = thread_rng();
    let mut map = BTreeMap::new();
    let mut total_size: u64 = 0;

    // Convert size to bytes
    let size_in_bytes = size_in_kb * 1024;

    while total_size < size_in_bytes {
        // Generate a random 32-byte key
        let key: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        // Randomly decide if the value is `None` or a `Vec<u8>` of random length
        let value: Option<Vec<u8>> = if rng.gen_bool(0.1) {
            None
        } else {
            let value_size: usize = rng.gen_range(1..=2048);
            Some((0..value_size).map(|_| rng.gen::<u8>()).collect())
        };

        // Calculate the size of the key and value
        let key_size = key.len() as u64;
        let value_size = match &value {
            Some(v) => v.len() as u64 + 1,
            None => 1,
        };

        // Add to the map
        map.insert(
            Arc::from(key.into_boxed_slice()),
            value.map(|v| Arc::from(v.into_boxed_slice())),
        );

        // Update the total size
        total_size += key_size + value_size;
    }

    map
}

#[allow(clippy::too_many_arguments)]
pub fn create_serialized_fake_receipt_batch_proof(
    initial_state_root: [u8; 32],
    last_l2_height: u64,
    method_id: [u32; 8],
    state_diff: Option<CumulativeStateDiff>,
    malformed_journal: bool,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
    sequencer_commitments: Vec<SequencerCommitment>,
    prev_sequencer_commitment_hash: Option<[u8; 32]>,
) -> Vec<u8> {
    let sequencer_commitment_hashes = sequencer_commitments
        .iter()
        .map(|c| c.serialize_and_calculate_sha_256())
        .collect::<Vec<_>>();
    let previous_commitment_index = if sequencer_commitments[0].index == 1 {
        None
    } else {
        Some(sequencer_commitments[0].index - 1)
    };
    let mut state_roots = vec![initial_state_root];

    // For the sake of easiness of impl tests, we can use merkle root as state root
    state_roots.extend(sequencer_commitments.iter().map(|c| c.merkle_root));

    let batch_proof_output = BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
        state_roots,
        last_l2_height,
        final_l2_block_hash: [0u8; 32],
        state_diff: state_diff.unwrap_or_default(),
        sequencer_commitment_hashes,
        last_l1_hash_on_bitcoin_light_client_contract,
        sequencer_commitment_index_range: (
            sequencer_commitments[0].index,
            sequencer_commitments[sequencer_commitments.len() - 1].index,
        ),
        previous_commitment_index,
        previous_commitment_hash: prev_sequencer_commitment_hash,
    });
    let mut output_serialized = borsh::to_vec(&batch_proof_output).unwrap();

    // Distorts the output and make it unparsable
    if malformed_journal {
        output_serialized.push(1u8);
    }

    let claim = MaybePruned::Value(ReceiptClaim::ok(method_id, output_serialized.clone()));
    let fake_receipt = FakeReceipt::new(claim);
    // Receipt with verifiable claim
    let receipt = InnerReceipt::Fake(fake_receipt);
    bincode::serialize(&receipt).unwrap()
}
