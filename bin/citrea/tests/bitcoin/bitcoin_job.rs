use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{U32, U64};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::job::rpc::{DaJobRpcClient, JobInfoResponse, JobStatusFilter, RetryJobResponse};
use bitcoin_da::job::service::JobStatus;
use bitcoin_da::service::BitcoinService;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BitcoinConfig, LightClientProverConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use jsonrpsee::http_client::HttpClient;
use reth_tasks::TaskManager;
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::services::da::DaService;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::bitcoin::full_node::create_serialized_fake_receipt_batch_proof_with_state_roots;
use crate::bitcoin::light_client_test::create_random_state_diff;
use crate::bitcoin::utils::spawn_bitcoin_da_prover_service_with_rpc_server;

struct JobServiceTest {
    task_manager: Option<TaskManager>,
}

impl JobServiceTest {
    #[allow(clippy::too_many_arguments)]
    async fn test_job_lifecycle(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        da_service_client: &HttpClient,
        genesis_state_root: [u8; 32],
        batch_proof_method_id: [u32; 8],
        finalized_height: u64,
        commitment: &SequencerCommitment,
        commitment_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff = create_random_state_diff(10);
        let l1_hash = da.get_block_hash(finalized_height).await?;

        let proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root,
            20,
            batch_proof_method_id,
            Some(state_diff),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment.clone()],
            vec![commitment_state_root],
            None,
        );

        // Make sure we start with no jobs
        let all_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::All), None, None)
            .await?;
        assert!(all_jobs.is_empty());

        let job_id = da_service
            .send_transaction(DaTxRequest::ZKProof(proof))
            .await?;

        da.wait_mempool_len(2, None).await?;
        da.generate(1).await?;

        // Check that job is not active anymore and has been processed
        let active_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Active), None, None)
            .await?;
        assert!(active_jobs.is_empty());

        // Check Completed status
        let completed_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Completed), None, None)
            .await?;
        assert_eq!(completed_jobs.len(), 1);

        let completed_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Terminal), None, None)
            .await?;
        assert_eq!(completed_jobs.len(), 1);

        let job_by_id: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;

        assert_eq!(job_by_id.status, JobStatus::Completed);
        assert_eq!(job_by_id.sent_count, 1);
        assert_eq!(job_by_id.error, None);

        Ok(())
    }

    /// Test job cancellation for in-progress jobs
    /// Test job retry for cancelled jobs
    #[allow(clippy::too_many_arguments)]
    async fn test_job_cancellation_and_retry(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        da_service_client: &HttpClient,
        genesis_state_root: [u8; 32],
        batch_proof_method_id: [u32; 8],
        finalized_height: u64,
        commitment: &SequencerCommitment,
        commitment_state_root: [u8; 32],
    ) -> Result<()> {
        let l1_hash = da.get_block_hash(finalized_height).await?;

        // Create a 400kb proof that will hit mempool limits and get stuck in progress
        let state_diff_100kb = create_random_state_diff(400);
        let proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root,
            20,
            batch_proof_method_id,
            Some(state_diff_100kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment.clone()],
            vec![commitment_state_root],
            None,
        );

        let job_id = da_service
            .send_transaction(DaTxRequest::ZKProof(proof.clone()))
            .await?;

        // Last tx chunk should hit mempool policy `DEFAULT_DESCENDANT_SIZE_LIMIT_KVB` limit
        // The three first proofs should hit the mempool + 1 chunk
        da.wait_mempool_len(18, None).await?;

        assert_eq!(da.get_raw_mempool().await?.len(), 18);

        let job_by_id: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;
        assert_eq!(job_by_id.status, JobStatus::InProgress);
        assert_eq!(job_by_id.sent_count, 9); // 9 commit/reveal pair

        // Cancel job
        let cancel_job_response = da_service_client.da_job_cancel(job_id).await?;
        assert_eq!(cancel_job_response.success, true);

        let job_by_id: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;
        assert_eq!(job_by_id.status, JobStatus::Cancelled);

        // Mine sent txs
        da.generate(1).await?;

        // Make sure job doesn't get processed after freeing space in mempool
        let res = da_service
            .wait_for_completion(job_id, Some(Duration::from_secs(5)))
            .await;
        assert!(res.is_err());

        let retry_job_response: RetryJobResponse = da_service_client.da_job_retry(job_id).await?;

        let old_job_by_id: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;
        assert_eq!(old_job_by_id.status, JobStatus::Cancelled);

        let new_job_by_id: JobInfoResponse = da_service_client
            .da_job_get_info(retry_job_response.new_job_id)
            .await?;
        assert_eq!(new_job_by_id.status, JobStatus::Pending);
        da.generate(1).await?;

        // Last tx chunk should hit mempool policy `DEFAULT_DESCENDANT_SIZE_LIMIT_KVB` limit
        // The three first proofs should hit the mempool + 1 chunk
        da.wait_mempool_len(18, None).await?;

        assert_eq!(da.get_raw_mempool().await?.len(), 18);

        let new_job_by_id: JobInfoResponse = da_service_client
            .da_job_get_info(retry_job_response.new_job_id)
            .await?;
        assert_eq!(new_job_by_id.status, JobStatus::InProgress);
        da.generate(1).await?;

        let res = da_service
            .wait_for_completion(retry_job_response.new_job_id, None)
            .await;
        assert!(res.is_ok());

        let new_job_by_id: JobInfoResponse = da_service_client
            .da_job_get_info(retry_job_response.new_job_id)
            .await?;
        assert_eq!(new_job_by_id.status, JobStatus::Completed);

        Ok(())
    }

    /// Test job listing with various filters and pagination
    #[allow(clippy::too_many_arguments)]
    async fn test_job_listing(
        &self,
        da: &BitcoinNode,
        da_service: &BitcoinService,
        da_service_client: &HttpClient,
        genesis_state_root: [u8; 32],
        batch_proof_method_id: [u32; 8],
        finalized_height: u64,
        commitment: &SequencerCommitment,
        commitment_state_root: [u8; 32],
    ) -> Result<()> {
        let state_diff = create_random_state_diff(400);
        let l1_hash = da.get_block_hash(finalized_height).await?;

        let proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root,
            20,
            batch_proof_method_id,
            Some(state_diff),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment.clone()],
            vec![commitment_state_root],
            None,
        );

        // Create multiple jobs to check list handling
        let job_id_1 = da_service
            .send_transaction(DaTxRequest::ZKProof(proof.clone()))
            .await?;

        da.wait_mempool_len(18, None).await?;

        // List all jobs
        let all_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::All), None, None)
            .await?;
        assert!(all_jobs.len() >= 3);

        // List active jobs
        let active_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Active), None, None)
            .await?;
        assert_eq!(active_jobs.len(), 1);

        // List cancelled jobs
        let cancelled_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Cancelled), None, None)
            .await?;
        assert_eq!(cancelled_jobs.len(), 1);

        // List failed jobs
        let failed_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Failed), None, None)
            .await?;
        assert_eq!(failed_jobs.len(), 0);

        // Test pagination
        let first_page = da_service_client
            .da_job_list(Some(JobStatusFilter::All), Some(1), Some(0))
            .await?;
        assert_eq!(first_page.len(), 1);

        // Test pagination
        let second_page = da_service_client
            .da_job_list(Some(JobStatusFilter::All), Some(1), Some(1))
            .await?;
        assert_eq!(second_page.len(), 1);

        // Make sure we don't get the same job_id
        assert_ne!(first_page[0].job_id, second_page[0].job_id);

        // Verify uuidv7 chronological ordering
        assert!(first_page[0].created_at <= second_page[0].created_at,);

        // Test limit
        let limited_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::All), Some(2), None)
            .await?;
        assert_eq!(limited_jobs.len(), 2);

        // Mine all sent txs
        da.generate(1).await?;

        let res = da_service.wait_for_completion(job_id_1, None).await;
        assert!(res.is_ok());

        // Verify completed jobs
        let completed_jobs = da_service_client
            .da_job_list(Some(JobStatusFilter::Completed), None, None)
            .await?;
        assert_eq!(completed_jobs.len(), 3);

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn test_job_persistence(
        &mut self,
        da: &BitcoinNode,
        da_service: Arc<BitcoinService>,
        da_service_client: HttpClient,
        genesis_state_root: [u8; 32],
        batch_proof_method_id: [u32; 8],
        finalized_height: u64,
        commitment: &SequencerCommitment,
        commitment_state_root: [u8; 32],
    ) -> Result<()> {
        let l1_hash = da.get_block_hash(finalized_height).await?;
        let state_diff_400kb = create_random_state_diff(400);
        let proof = create_serialized_fake_receipt_batch_proof_with_state_roots(
            genesis_state_root,
            20,
            batch_proof_method_id,
            Some(state_diff_400kb),
            false,
            l1_hash.as_raw_hash().to_byte_array(),
            vec![commitment.clone()],
            vec![commitment_state_root],
            None,
        );

        let job_id = da_service
            .send_transaction(DaTxRequest::ZKProof(proof))
            .await?;

        da.wait_mempool_len(18, None).await?;
        assert_eq!(da.get_raw_mempool().await?.len(), 18);

        let job_before: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;
        assert_eq!(job_before.job_id, job_id);
        assert_eq!(job_before.status, JobStatus::InProgress);
        assert_eq!(job_before.sent_count, 9);

        let active_jobs_before = da_service_client
            .da_job_list(Some(JobStatusFilter::Active), None, None)
            .await?;
        assert_eq!(active_jobs_before.len(), 1);
        assert_eq!(active_jobs_before[0].job_id, job_id);

        // Send graceful shutdown to da_service and drop da_service
        drop(da_service);
        drop(da_service_client);
        self.task_manager.take().unwrap().graceful_shutdown();
        sleep(Duration::from_secs(5)).await;

        // Create a new task_manager as previous was consumed
        self.task_manager = Some(TaskManager::current());
        let task_executor = self.task_manager.as_ref().unwrap().executor();

        let (da_service, da_service_client) = spawn_bitcoin_da_prover_service_with_rpc_server(
            &task_executor,
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let job_after: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;

        assert_eq!(job_after.job_id, job_before.job_id);
        assert_eq!(job_after.status, job_before.status);
        assert_eq!(job_after.created_at, job_before.created_at);
        assert_eq!(job_after.sent_count, job_before.sent_count);

        let active_jobs_after = da_service_client
            .da_job_list(Some(JobStatusFilter::Active), None, None)
            .await?;
        assert_eq!(active_jobs_after.len(), 1);
        assert_eq!(active_jobs_after[0].job_id, job_id);
        assert_eq!(active_jobs_after[0].status, JobStatus::InProgress);

        da.generate(1).await?;

        da.wait_mempool_len(6, None).await?;
        let res = da_service.wait_for_completion(job_id, None).await;
        assert!(res.is_ok());

        let completed_job: JobInfoResponse = da_service_client.da_job_get_info(job_id).await?;
        assert_eq!(completed_job.status, JobStatus::Completed);
        assert_eq!(completed_job.created_at, job_before.created_at);
        assert_eq!(completed_job.error, None);

        let active_jobs_final = da_service_client
            .da_job_list(Some(JobStatusFilter::Active), None, None)
            .await?;
        assert_eq!(active_jobs_final.len(), 0);

        Ok(())
    }
}

#[async_trait]
impl TestCase for JobServiceTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            with_sequencer: true,
            with_light_client_prover: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec![
                "-persistmempool=0",
                "-walletbroadcast=0",
                "-limitancestorcount=100",
                "-limitdescendantcount=100",
                "-fallbackfee=0.00001",
            ],
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 171,
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .unwrap()
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.as_ref().unwrap().executor();
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        let sequencer = f.sequencer.as_mut().unwrap();
        let full_node = f.full_node.as_mut().unwrap();
        let light_client_prover = f.light_client_prover.as_mut().unwrap();

        // Common setup
        let (da_service, da_service_client) = spawn_bitcoin_da_prover_service_with_rpc_server(
            &task_executor,
            &da.config,
            Self::test_config().dir,
        )
        .await;

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        light_client_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(finalized_height))
            .await?;
        let lcp_output = lcp.unwrap().light_client_proof_output;

        let batch_proof_method_ids = light_client_prover
            .client
            .http_client()
            .get_batch_proof_method_ids()
            .await?;
        let genesis_state_root = lcp_output.l2_state_root;

        // Generate sequencer commitment
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        full_node.wait_for_l1_height(finalized_height, None).await?;

        let commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?
            .map(|c| SequencerCommitment {
                merkle_root: c.merkle_root,
                l2_end_block_number: c.l2_end_block_number.to::<u64>(),
                index: c.index.to::<u32>(),
            })
            .unwrap();

        let commitment_state_root = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment.l2_end_block_number))
            .await?
            .unwrap()
            .header
            .state_root;

        let batch_proof_method_id: [u32; 8] = batch_proof_method_ids[0].method_id.into();

        self.test_job_lifecycle(
            da,
            &da_service,
            &da_service_client,
            genesis_state_root,
            batch_proof_method_id,
            finalized_height,
            &commitment,
            commitment_state_root,
        )
        .await?;

        // Clean mempool between each step
        da.generate(1).await?;

        self.test_job_cancellation_and_retry(
            da,
            &da_service,
            &da_service_client,
            genesis_state_root,
            batch_proof_method_id,
            finalized_height,
            &commitment,
            commitment_state_root,
        )
        .await?;

        // Clean mempool between each step
        da.generate(1).await?;

        self.test_job_listing(
            da,
            &da_service,
            &da_service_client,
            genesis_state_root,
            batch_proof_method_id,
            finalized_height,
            &commitment,
            commitment_state_root,
        )
        .await?;
        // Clean mempool between each step
        da.generate(1).await?;

        self.test_job_persistence(
            da,
            da_service,
            da_service_client,
            genesis_state_root,
            batch_proof_method_id,
            finalized_height,
            &commitment,
            commitment_state_root,
        )
        .await?;

        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bitcoin_job_service() -> Result<()> {
    TestCaseRunner::new(JobServiceTest {
        task_manager: Some(TaskManager::current()),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
