//! Provides the RPC interface for the bitcoin-da job da.
//! The namespace for these RPC methods is "da" (Data Availability).
//! This module defines methods to interact with bitcoin-da jobs,
//! including cancelling, retrying and listing jobs.

use std::sync::Arc;

use citrea_common::rpc::utils::internal_rpc_error;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

use super::Result;
use crate::job::service::{Job, JobId, JobProgress, JobStatus};
use crate::service::BitcoinService;

/// RPC provider trait for da job da
pub(super) trait DaJobRpcProvider {
    /// Cancel a pending or in-progress job by job id
    ///
    /// # Arguments
    /// * `job_id` - The job uuid
    ///
    /// # Returns
    /// * `Ok(())` if the job was successfully cancelled
    /// * `Err` if the job doesn't exist, is already completed, or cannot be cancelled
    fn cancel_job(&self, job_id: JobId) -> Result<()>;

    /// Retry a failed or cancelled job by creating a new job with the same data
    ///
    /// # Arguments
    /// * `job_id` - The unique identifier of the job to retry
    ///
    /// # Returns
    /// * `Ok(JobId)` - The ID of the newly created retry job
    /// * `Err` if the job doesn't exist or is not in a retryable state
    fn retry_job(&self, job_id: JobId) -> Result<JobId>;

    /// List jobs with optional filtering and pagination
    ///
    /// # Arguments
    /// * `filter` - Optional filter criteria for jobs
    ///
    /// # Returns
    /// * `Ok(Vec<JobInfoResponse>)` - List of jobs matching the filter criteria
    /// * `Err` on database or serialization errors
    fn list_jobs(&self, filter: JobListFilter) -> Result<Vec<(Job, JobProgress)>>;

    /// Get detailed information about a specific job
    ///
    /// # Arguments
    /// * `job_id` - The unique identifier of the job
    ///
    /// # Returns
    /// * `Ok(JobInfoResponse)` - Detailed information about the job
    /// * `Err` on database error
    fn get_job_info(&self, job_id: JobId) -> Result<(Job, JobProgress)>;
}

/// Filter criteria for listing jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobListFilter {
    /// Optional status filter (e.g., only show "Pending" jobs)
    pub status: Option<JobStatusFilter>,
    /// Maximum number of jobs to return (default: 100, max: 1000)
    pub limit: Option<usize>,
    /// Skip first N jobs (for pagination)
    pub offset: Option<usize>,
}

impl Default for JobListFilter {
    fn default() -> Self {
        Self {
            status: None,
            limit: Some(100),
            offset: None,
        }
    }
}

/// Job status filter for RPC queries
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatusFilter {
    /// Only pending jobs
    Pending,
    /// Only in-progress jobs
    InProgress,
    /// Only completed jobs
    Completed,
    /// Only cancelled jobs
    Cancelled,
    /// Only failed jobs
    Failed,
    /// All active jobs (Pending + InProgress)
    Active,
    /// All terminal jobs (Completed + Cancelled + Failed)
    Terminal,
    /// All jobs
    #[default]
    All,
}

impl JobStatusFilter {
    /// Convert filter to list of status codes to query
    pub(super) fn to_status_codes(&self) -> Vec<u8> {
        match self {
            JobStatusFilter::Pending => vec![JobStatus::Pending.as_u8()],
            JobStatusFilter::InProgress => vec![JobStatus::InProgress.as_u8()],
            JobStatusFilter::Completed => vec![JobStatus::Completed.as_u8()],
            JobStatusFilter::Cancelled => vec![JobStatus::Cancelled.as_u8()],
            JobStatusFilter::Failed => {
                vec![JobStatus::Failed {
                    error: String::new(),
                }
                .as_u8()]
            }
            JobStatusFilter::Active => {
                vec![JobStatus::Pending.as_u8(), JobStatus::InProgress.as_u8()]
            }
            JobStatusFilter::Terminal => vec![
                JobStatus::Completed.as_u8(),
                JobStatus::Cancelled.as_u8(),
                JobStatus::Failed {
                    error: String::new(),
                }
                .as_u8(),
            ],
            JobStatusFilter::All => vec![
                JobStatus::Pending.as_u8(),
                JobStatus::InProgress.as_u8(),
                JobStatus::Completed.as_u8(),
                JobStatus::Cancelled.as_u8(),
                JobStatus::Failed {
                    error: String::new(),
                }
                .as_u8(),
            ],
        }
    }
}

/// Detailed information about a job for RPC responses
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobInfoResponse {
    /// Unique job identifier
    pub job_id: JobId,
    /// Current job status
    pub status: JobStatus,
    /// Job creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Last update timestamp (Unix seconds)
    pub last_updated: u64,
    /// Number of transactions already sent
    pub sent_count: usize,
    /// Error message if job failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JobInfoResponse {
    /// Create JobInfoResponse from Job and JobProgress
    fn from_job_and_progress((job, progress): (Job, JobProgress)) -> Self {
        let error = match &progress.status {
            JobStatus::Failed { error } => Some(error.clone()),
            _ => None,
        };

        Self {
            job_id: job.id,
            status: progress.status.clone(),
            created_at: job.created_at,
            last_updated: progress.last_updated,
            sent_count: progress.sent_chunks.count(),
            error,
        }
    }
}

/// Response for job cancellation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelJobResponse {
    /// Whether the job was successfully cancelled
    pub success: bool,
}

/// Response for job retry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryJobResponse {
    /// uuid of the newly created retry job
    pub new_job_id: JobId,
    /// uuid of the original job that was retried
    pub original_job_id: JobId,
}

#[rpc(client, server, namespace = "daJob")]
pub trait DaJobRpc {
    /// Cancels a pending or in-progress job.
    ///
    /// # Arguments
    /// * `job_id` - The unique identifier of the job to cancel
    ///
    /// # Returns
    /// * Success response
    ///
    /// # Errors
    /// * Job not found
    /// * Job cannot be cancelled (already completed, failed, or cancelled)
    #[method(name = "cancel")]
    async fn da_job_cancel(&self, job_id: JobId) -> RpcResult<CancelJobResponse>;

    /// Retries a failed or cancelled job by creating a new job with the same data.
    ///
    /// # Arguments
    /// * `job_id` - The unique identifier of the job to retry
    ///
    /// # Returns
    /// * Response containing the new job ID
    ///
    /// # Errors
    /// * Job not found
    /// * Job is not in a retryable state (pending, in-progress, or completed)
    #[method(name = "retry")]
    async fn da_job_retry(&self, job_id: JobId) -> RpcResult<RetryJobResponse>;

    /// Lists jobs with optional filtering and pagination.
    ///
    /// # Arguments
    /// * `status` - Optional status filter (pending, inProgress, completed, cancelled, failed, active, terminal)
    /// * `limit` - Maximum number of jobs to return (default: 100, max: 1000)
    /// * `offset` - Number of jobs to skip for pagination (default: 0)
    ///
    /// # Returns
    /// * List of job information matching the filter criteria
    #[method(name = "list")]
    async fn da_job_list(
        &self,
        status: Option<JobStatusFilter>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> RpcResult<Vec<JobInfoResponse>>;

    /// Gets detailed information about a specific job.
    ///
    /// # Arguments
    /// * `job_id` - The unique identifier of the job
    ///
    /// # Returns
    /// * Detailed job information including status, timestamps, and progress
    ///
    /// # Errors
    /// * Database error related errors
    #[method(name = "get")]
    async fn da_job_get_info(&self, job_id: JobId) -> RpcResult<JobInfoResponse>;
}

/// The implementation of the RPC itself.
pub struct DaJobRpcServerImpl {
    da: Arc<BitcoinService>,
}

impl DaJobRpcServerImpl {
    /// Create a new RPC server implementation
    pub fn new(da: Arc<BitcoinService>) -> Self {
        Self { da }
    }
}

#[async_trait::async_trait]
impl DaJobRpcServer for DaJobRpcServerImpl {
    async fn da_job_cancel(&self, job_id: JobId) -> RpcResult<CancelJobResponse> {
        self.da
            .job_service
            .cancel_job(job_id)
            .map(|_| CancelJobResponse { success: true })
            .map_err(internal_rpc_error)
    }

    async fn da_job_retry(&self, job_id: JobId) -> RpcResult<RetryJobResponse> {
        self.da
            .job_service
            .retry_job(job_id)
            .map(|new_job_id| RetryJobResponse {
                new_job_id,
                original_job_id: job_id,
            })
            .map_err(internal_rpc_error)
    }

    async fn da_job_list(
        &self,
        status: Option<JobStatusFilter>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> RpcResult<Vec<JobInfoResponse>> {
        let filter = JobListFilter {
            status,
            limit,
            offset,
        };

        Ok(self
            .da
            .job_service
            .list_jobs(filter)
            .map_err(internal_rpc_error)?
            .into_iter()
            .map(JobInfoResponse::from_job_and_progress)
            .collect())
    }

    async fn da_job_get_info(&self, job_id: JobId) -> RpcResult<JobInfoResponse> {
        self.da
            .job_service
            .get_job_info(job_id)
            .map_err(internal_rpc_error)
            .map(JobInfoResponse::from_job_and_progress)
    }
}

/// Creates a new RPC module for the DA Job da.
///
/// # Arguments
/// * `da.job_service` - Arc reference to the job da
///
/// # Returns
/// * JSON-RPC module ready to be merged into the server
pub fn create_rpc_module(da: Arc<BitcoinService>) -> jsonrpsee::RpcModule<DaJobRpcServerImpl> {
    let server = DaJobRpcServerImpl::new(da);
    DaJobRpcServer::into_rpc(server)
}
