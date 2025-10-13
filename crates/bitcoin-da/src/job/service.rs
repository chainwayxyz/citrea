use std::time::{Duration, Instant};

use bitcoin::{Transaction, Txid};
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::DaLedgerOps;
pub use sov_db::schema::types::da_jobs::{Job, JobId, JobStatus};
use sov_db::schema::types::da_jobs::{JobProgress as DbJobProgress, SentChunks as DbSentChunks};
use tracing::{info, instrument};

use crate::helpers::builders::body_builders::RawTxData;
use crate::helpers::get_timestamp;
use crate::job::error::JobServiceError;
use crate::job::rpc::{DaJobRpcProvider, JobListFilter};

type Result<T> = std::result::Result<T, JobServiceError>;

/// Tracks progress of a job including sent transactions for recovery.
///
/// This state is persisted to the database and updated as transactions
/// are sent to bitcoin da.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    /// Job id as uuidv7
    pub job_id: JobId,
    /// Current job status
    pub status: JobStatus,
    /// Partially sent commit/reveal chunks for partial sending and recovery
    pub sent_chunks: SentChunks,
    /// Last update timestamp
    pub last_updated: u64,
}

impl JobProgress {
    fn new(job_id: JobId, last_updated: u64) -> Self {
        Self {
            job_id,
            status: JobStatus::Pending,
            sent_chunks: SentChunks::new(),
            last_updated,
        }
    }
}

/// Track sent chunk for partial sending and recovery
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SentChunks {
    /// Sent commit txs
    pub commit_txs: Vec<Transaction>,
    /// Sent reveal txs
    pub reveal_txs: Vec<Transaction>,
}

impl SentChunks {
    /// Return a default SentChunk with empty vectors
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of sent chunks
    pub fn count(&self) -> usize {
        self.reveal_txs.len()
    }

    /// Extend with sent commit and reveal chunks
    pub fn extend(&mut self, commits: Vec<Transaction>, reveals: Vec<Transaction>) {
        self.commit_txs.extend(commits);
        self.reveal_txs.extend(reveals);
    }
}

impl From<DbSentChunks> for SentChunks {
    fn from(db_chunks: DbSentChunks) -> Self {
        let commit_txs = db_chunks
            .commit_txs
            .iter()
            .map(|bytes| {
                bitcoin::consensus::deserialize(bytes)
                    .expect("Failed to deserialize commit transaction from database")
            })
            .collect();

        let reveal_txs = db_chunks
            .reveal_txs
            .iter()
            .map(|bytes| {
                bitcoin::consensus::deserialize(bytes)
                    .expect("Failed to deserialize reveal transaction from database")
            })
            .collect();

        Self {
            commit_txs,
            reveal_txs,
        }
    }
}

impl From<SentChunks> for DbSentChunks {
    fn from(chunks: SentChunks) -> Self {
        let commit_txs = chunks
            .commit_txs
            .iter()
            .map(bitcoin::consensus::serialize)
            .collect();

        let reveal_txs = chunks
            .reveal_txs
            .iter()
            .map(bitcoin::consensus::serialize)
            .collect();

        Self {
            commit_txs,
            reveal_txs,
        }
    }
}

impl From<DbJobProgress> for JobProgress {
    fn from(db_progress: DbJobProgress) -> Self {
        Self {
            job_id: db_progress.job_id,
            status: db_progress.status,
            sent_chunks: db_progress.sent_chunks.into(),
            last_updated: db_progress.last_updated,
        }
    }
}

impl From<JobProgress> for DbJobProgress {
    fn from(progress: JobProgress) -> Self {
        Self {
            job_id: progress.job_id,
            status: progress.status,
            sent_chunks: progress.sent_chunks.into(),
            last_updated: progress.last_updated,
        }
    }
}

/// Job service
pub struct DaJobService<DB: DaLedgerOps> {
    ledger_db: DB,
}

impl<DB: DaLedgerOps> DaJobService<DB> {
    /// Creates a new DaJobService with ledger_db
    pub fn new(ledger_db: DB) -> Self {
        Self { ledger_db }
    }

    /// Create a new job and save to db
    #[instrument(level = "trace", skip(self), ret)]
    pub fn submit_job(&self, raw_tx_data: RawTxData) -> Result<JobId> {
        let job_id = uuid::Uuid::now_v7();
        let created_at = get_timestamp();

        // Serialize RawTxData to Vec<u8>
        let data = borsh::to_vec(&raw_tx_data)?;

        let job = Job::new(job_id, data, created_at);
        let progress = JobProgress::new(job_id, created_at);

        self.insert_job(&job)?;
        self.upsert_progress(&progress)?;
        self.ledger_db
            .insert_job_status_index(progress.status.as_u8(), job_id)?;

        info!("Job {job_id} submitted and persisted");
        Ok(job_id)
    }

    /// Save a new job to db
    #[instrument(level = "trace", skip(self))]
    fn insert_job(&self, job: &Job) -> Result<()> {
        self.ledger_db
            .insert_job(job.id, job)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Get a job by id
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_job(&self, job_id: &JobId) -> Result<Option<Job>> {
        self.ledger_db
            .get_job(job_id)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Upsert job progress - convert local JobProgress to DB format
    #[instrument(level = "trace", skip(self))]
    pub(crate) fn upsert_progress(&self, progress: &JobProgress) -> Result<()> {
        let db_progress: DbJobProgress = progress.clone().into();

        self.ledger_db
            .upsert_progress(&progress.job_id, &db_progress)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Retrieve job progress by id and convert to local format
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_progress(&self, job_id: &JobId) -> Result<Option<JobProgress>> {
        let db_progress = self
            .ledger_db
            .get_progress(job_id)
            .map_err(JobServiceError::DatabaseError)?;

        Ok(db_progress.map(|p| p.into()))
    }

    /// Get all `Pending` and `InProgress` job ids from storage
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_all_active_job_ids(&self) -> Result<Vec<JobId>> {
        let mut active_jobs = Vec::new();

        active_jobs.extend(
            self.ledger_db
                .get_job_ids_by_status(JobStatus::Pending.as_u8())?,
        );

        active_jobs.extend(
            self.ledger_db
                .get_job_ids_by_status(JobStatus::InProgress.as_u8())?,
        );

        // Sort uuidv7 chronologically
        active_jobs.sort();

        Ok(active_jobs)
    }

    /// Update job status by id
    #[instrument(level = "debug", skip(self))]
    pub fn update_job_status(&self, progress: &mut JobProgress, status: JobStatus) -> Result<()> {
        let old_status = progress.status.as_u8();
        let new_status = status.as_u8();

        progress.status = status;
        progress.last_updated = get_timestamp();

        self.upsert_progress(progress)?;

        // Update status indexing
        if old_status != new_status {
            self.ledger_db
                .remove_job_status_index(old_status, progress.job_id)?;
            self.ledger_db
                .insert_job_status_index(new_status, progress.job_id)?;
        }

        Ok(())
    }

    /// Record sending DA transactions and keep track of sent chunks and reveals
    #[instrument(level = "debug", skip(self))]
    pub fn record_sent_transactions(
        &self,
        progress: &mut JobProgress,
        commits: Vec<Transaction>,
        reveals: Vec<Transaction>,
    ) -> Result<()> {
        progress.sent_chunks.extend(commits, reveals);
        self.update_job_status(progress, JobStatus::InProgress)
    }

    /// Get all pending commit and reveals txids.
    ///
    /// This is required for removing from the utxo set and prevent selecting UTXOs twice
    #[instrument(level = "trace", skip_all, ret)]
    pub(crate) fn get_pending_chunks(&self) -> Result<Vec<Txid>> {
        let mut txids = Vec::new();

        let active_job_ids = self.get_all_active_job_ids()?;
        for job_id in active_job_ids {
            if let Some(progress) = self.get_progress(&job_id)? {
                if matches!(progress.status, JobStatus::InProgress) {
                    txids.extend(
                        progress
                            .sent_chunks
                            .commit_txs
                            .iter()
                            .map(|tx| tx.compute_txid()),
                    );
                    txids.extend(
                        progress
                            .sent_chunks
                            .reveal_txs
                            .iter()
                            .map(|tx| tx.compute_txid()),
                    );
                }
            }
        }

        Ok(txids)
    }

    /// Wait for job completion and return the transaction ID
    #[instrument(level = "debug", skip(self, timeout), ret)]
    pub async fn wait_for_completion(
        &self,
        job_id: JobId,
        timeout: Option<Duration>,
    ) -> Result<Txid> {
        let start = Instant::now();
        let timeout = timeout.unwrap_or(Duration::from_secs(600)); // Defaults to 10min

        loop {
            if start.elapsed() > timeout {
                return Err(JobServiceError::JobTimeout(job_id, timeout.as_secs()));
            }

            let progress = self
                .get_progress(&job_id)?
                .ok_or(JobServiceError::JobNotFound(job_id))?;

            match progress.status {
                JobStatus::Completed => {
                    if let Some(last_reveal) = progress.sent_chunks.reveal_txs.last() {
                        return Ok(last_reveal.compute_txid());
                    }
                    return Err(JobServiceError::NoTransactionsFound(job_id));
                }
                JobStatus::Failed { error, .. } => {
                    return Err(JobServiceError::JobFailed(job_id, error));
                }
                JobStatus::Cancelled => {
                    return Err(JobServiceError::JobCancelled(job_id));
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Check if any job is in progress.
    pub async fn has_job_in_progress(&self) -> Result<bool> {
        let in_progress_jobs = self
            .ledger_db
            .get_job_ids_by_status(JobStatus::InProgress.as_u8())?;

        Ok(!in_progress_jobs.is_empty())
    }
}

/// Implementation of RPC provider methods
impl<DB: DaLedgerOps> DaJobRpcProvider for DaJobService<DB> {
    fn cancel_job(&self, job_id: JobId) -> Result<()> {
        // Get job progress to check status
        let mut progress = self
            .get_progress(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))?;

        // Only allow cancellation of pending or in-progress jobs
        match progress.status {
            JobStatus::Pending | JobStatus::InProgress => {
                self.update_job_status(&mut progress, JobStatus::Cancelled)?;
                tracing::info!("Job {job_id} successfully cancelled");
                Ok(())
            }
            JobStatus::Completed | JobStatus::Cancelled | JobStatus::Failed { .. } => Err(
                JobServiceError::JobCancellationFailure(job_id, progress.status),
            ),
        }
    }

    fn retry_job(&self, job_id: JobId) -> Result<JobId> {
        // Get job progress to check status
        let progress = self
            .get_progress(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))?;

        // Only allow retry of failed or cancelled jobs
        match progress.status {
            JobStatus::Failed { .. } | JobStatus::Cancelled => {
                // Get original job and deserialize data
                let original_job = self
                    .get_job(&job_id)?
                    .ok_or(JobServiceError::JobNotFound(job_id))?;

                let raw_data: RawTxData = borsh::from_slice(&original_job.data)?;

                // Create new job with same data
                let new_job_id = self.submit_job(raw_data)?;
                tracing::info!("Job {job_id} retried as new job {new_job_id}");
                Ok(new_job_id)
            }
            JobStatus::Pending | JobStatus::InProgress | JobStatus::Completed => {
                Err(JobServiceError::JobRetryFailure(job_id, progress.status))
            }
        }
    }

    fn list_jobs(&self, filter: JobListFilter) -> Result<Vec<(Job, JobProgress)>> {
        let limit = filter.limit.unwrap_or(25).min(1000); // Defaults to 25, capped at 1000
        let offset = filter.offset.unwrap_or(0);

        // Get job ids based on status filter
        let status_filter = filter.status.unwrap_or_default();

        let mut job_ids = Vec::new();
        for code in status_filter.to_status_codes() {
            job_ids.extend(self.ledger_db.get_job_ids_by_status(code)?);
        }
        job_ids.sort(); // sort chronologically by uuidv7

        // Apply pagination
        // TODO paginate at the db level. This should be sufficient for now as we take/skip on uuid before fetching job info
        let job_ids: Vec<_> = job_ids.into_iter().skip(offset).take(limit).collect();

        // Return (job, progress) per id
        let mut job_infos = Vec::new();
        for job_id in job_ids {
            if let (Some(job), Some(progress)) =
                (self.get_job(&job_id)?, self.get_progress(&job_id)?)
            {
                job_infos.push((job, progress));
            }
        }

        Ok(job_infos)
    }

    fn get_job_info(&self, job_id: JobId) -> Result<(Job, JobProgress)> {
        let job = self
            .get_job(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))?;

        let progress = self
            .get_progress(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))?;

        Ok((job, progress))
    }
}
