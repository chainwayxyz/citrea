use std::time::{Duration, Instant};

use bitcoin::{Transaction, Txid};
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::DaLedgerOps;
use tracing::{info, instrument};
use uuid::Uuid;

use crate::helpers::builders::body_builders::RawTxData;
use crate::helpers::get_timestamp;
use crate::job::error::JobServiceError;

/// Unique job id using uuidv7 for ordering by creation time
pub(crate) type JobId = Uuid;

type Result<T> = std::result::Result<T, JobServiceError>;

/// Job status representing the current state of transaction processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    /// Job is queued and waiting to be processed
    Pending,
    /// Job is in progress
    InProgress,
    /// Job completed successfully
    Completed,
    /// Job was cancelled before completion
    Cancelled,
    /// Job failed with error
    Failed {
        /// Error associated to the failure
        error: String,
    },
}

impl JobStatus {
    /// u8 representation of `JobStatus`
    pub fn as_u8(&self) -> u8 {
        match self {
            JobStatus::Pending => 0,
            JobStatus::InProgress => 1,
            JobStatus::Completed => 2,
            JobStatus::Cancelled => 3,
            JobStatus::Failed { .. } => 4,
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Job {
    /// Job id as uuidv7
    pub id: JobId,
    /// Raw job data
    pub data: RawTxData,
    /// Time of job creation
    pub created_at: u64,
}

impl Job {
    pub(crate) fn new(data: RawTxData) -> Self {
        Self {
            id: Uuid::now_v7(),
            data,
            created_at: get_timestamp(),
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
    pub fn submit_job(&self, raw_tx_data: RawTxData) -> Result<Job> {
        let job = Job::new(raw_tx_data);
        let job_id = job.id;

        let progress = JobProgress::new(job_id, job.created_at);

        self.insert_job(&job)?;
        self.upsert_progress(&progress)?;
        self.ledger_db
            .insert_job_status_index(progress.status.as_u8(), job_id)?;

        info!("Job {job_id} submitted and persisted");
        Ok(job)
    }

    /// Save a new job to db
    #[instrument(level = "trace", skip(self))]
    fn insert_job(&self, job: &Job) -> Result<()> {
        let value = bincode::serialize(job)?;
        self.ledger_db
            .insert_job(job.id, value)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Get a job by id
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_job(&self, job_id: &JobId) -> Result<Option<Job>> {
        let job = self
            .ledger_db
            .get_job(job_id)
            .map_err(JobServiceError::DatabaseError)?
            .map(|v| bincode::deserialize(&v))
            .transpose()?;
        Ok(job)
    }

    /// Upsert job progress after serialization
    #[instrument(level = "trace", skip(self))]
    pub(crate) fn upsert_progress(&self, progress: &JobProgress) -> Result<()> {
        let value = bincode::serialize(progress)?;
        self.ledger_db
            .upsert_progress(&progress.job_id, value)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Retrieve and deserialize job progress by id
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_progress(&self, job_id: &JobId) -> Result<Option<JobProgress>> {
        let progress = self
            .ledger_db
            .get_progress(job_id)
            .map_err(JobServiceError::DatabaseError)?
            .map(|v| bincode::deserialize(&v))
            .transpose()?;
        Ok(progress)
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

        // Sort uuidv7 chronogically
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
