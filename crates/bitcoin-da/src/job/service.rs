use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use lru::LruCache;
use parking_lot::Mutex;
use sov_db::ledger_db::DaLedgerOps;
use sov_db::schema::types::da_jobs::{DaJobStatus, JobId, JobProgress};
use sov_rollup_interface::da::DataOnDa;
use sov_rollup_interface::services::da::DaTxRequest;
use tokio::sync::oneshot;
use tracing::{info, instrument};
use uuid::Uuid;

use super::Result;
use crate::error::BitcoinServiceError;
use crate::helpers::builders::body_builders::RawTxData;
use crate::helpers::get_timestamp;
use crate::job::error::JobServiceError;
use crate::job::metrics::DA_JOB_METRICS as METRICS;
use crate::job::rpc::{DaJobRpcProvider, JobListFilter};
use crate::service::{split_proof, TxidWrapper};

type JobWaiters =
    HashMap<JobId, oneshot::Sender<std::result::Result<TxidWrapper, BitcoinServiceError>>>;

/// Job service
pub struct DaJobService<DB: DaLedgerOps> {
    ledger_db: DB,
    job_waiters: Arc<Mutex<JobWaiters>>,
    raw_tx_data_cache: Arc<Mutex<LruCache<JobId, RawTxData>>>,
}

impl<DB: DaLedgerOps> DaJobService<DB> {
    /// Creates a new `DaJobService` with `ledger_db`
    pub fn new(ledger_db: DB, cache_size: Option<NonZeroUsize>) -> Self {
        let cache_size = cache_size.unwrap_or_else(|| NonZeroUsize::new(10).unwrap());

        Self {
            ledger_db,
            job_waiters: Arc::new(Mutex::new(HashMap::new())),
            raw_tx_data_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        }
    }

    /// Create a new job and save to db
    pub fn submit_job(
        &self,
        da_tx_request: DaTxRequest,
        tx: oneshot::Sender<std::result::Result<TxidWrapper, BitcoinServiceError>>,
    ) -> Result<JobId> {
        let job_id = Uuid::now_v7();

        let progress = JobProgress::new(job_id, get_timestamp());

        self.ledger_db
            .submit_job(job_id, &da_tx_request, &progress)?;

        METRICS.record_job_submitted();

        self.job_waiters.lock().insert(job_id, tx);

        info!("Job {job_id} submitted and persisted");
        Ok(job_id)
    }

    /// Get a job data by id
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_job_request(&self, job_id: &JobId) -> Result<Option<DaTxRequest>> {
        self.ledger_db
            .get_job_request(job_id)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Retrieve job progress by id and convert to local format
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_progress(&self, job_id: &JobId) -> Result<Option<JobProgress>> {
        self.ledger_db
            .get_progress(job_id)
            .map_err(JobServiceError::DatabaseError)
    }

    /// Get the raw transaction data for a job
    ///
    /// This function attempts to retrieve the data from cache first.
    /// If not found in cache, it deserializes from the job data and
    /// transforms it into the appropriate RawTxData format.
    ///
    /// For StoredProof requests, it retrieves the actual proof from the database
    /// using the proof_id reference.
    ///
    /// # Arguments
    ///
    /// * `job` - The job containing serialized DaTxRequest data
    ///
    /// # Returns
    ///
    /// * `Result<RawTxData>` - The raw transaction data or an error
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_job_data(&self, job_id: Uuid, job_data: DaTxRequest) -> Result<RawTxData> {
        if let Some(data) = self.raw_tx_data_cache.lock().get(&job_id) {
            return Ok(data.to_owned());
        }

        let raw_tx_data = match job_data {
            DaTxRequest::ZKProof(zkproof) => split_proof(zkproof),
            DaTxRequest::StoredProof(proof_id) => {
                // Retrieve proof via secondary index
                let zkproof = self.ledger_db.get_proof_by_proof_id(proof_id)?;
                split_proof(zkproof)
            }
            DaTxRequest::SequencerCommitment(comm) => {
                let blob = borsh::to_vec(&DataOnDa::SequencerCommitment(comm))
                    .expect("SequencerCommitment serialize must not fail");
                Ok(RawTxData::SequencerCommitment(blob))
            }
            DaTxRequest::BatchProofMethodId(id) => {
                let blob = borsh::to_vec(&DataOnDa::BatchProofMethodId(id))
                    .expect("BatchProofMethodId serialize must not fail");
                Ok(RawTxData::BatchProofMethodId(blob))
            }
        }
        .context("Failed to retrieve RawTxData from DaTxRequest")?;

        self.raw_tx_data_cache
            .lock()
            .push(job_id, raw_tx_data.clone());

        Ok(raw_tx_data)
    }

    /// Get all `Pending` and `InProgress` job ids from storage
    #[instrument(level = "trace", skip(self), ret)]
    pub(crate) fn get_all_active_job_ids(&self) -> Result<Vec<JobId>> {
        let mut active_jobs = Vec::new();

        active_jobs.extend(
            self.ledger_db
                .get_job_ids_by_status(DaJobStatus::Pending.as_u8())?,
        );

        active_jobs.extend(
            self.ledger_db
                .get_job_ids_by_status(DaJobStatus::InProgress.as_u8())?,
        );

        // Sort uuidv7 chronologically
        active_jobs.sort();

        Ok(active_jobs)
    }

    /// Save job progress
    #[instrument(level = "debug", skip(self))]
    pub fn upsert_job_progress(&self, progress: &mut JobProgress) -> Result<()> {
        progress.last_updated = get_timestamp();

        self.ledger_db.upsert_progress(progress)?;

        Ok(())
    }

    /// Update and save job progress to a new status
    #[instrument(level = "debug", skip(self))]
    pub fn update_job_status(
        &self,
        progress: &mut JobProgress,
        new_status: DaJobStatus,
    ) -> Result<()> {
        let job_id = progress.job_id;
        let previous_status = progress.status.clone();

        progress.status = new_status;
        progress.last_updated = get_timestamp();

        let db_progress = progress.clone();
        self.ledger_db
            .upsert_progress_new_status(&db_progress, previous_status.as_u8())?;

        METRICS.record_status_update(&previous_status, progress);

        self.notify_new_status(job_id, progress);

        Ok(())
    }

    /// Get all pending commit and reveals txids.
    ///
    /// This is required for removing from the utxo set and prevent selecting UTXOs twice
    #[instrument(level = "trace", skip_all, ret)]
    pub(crate) fn get_pending_chunks(&self) -> Result<HashSet<Txid>> {
        let mut txids = HashSet::new();

        let active_job_ids = self.get_all_active_job_ids()?;
        for job_id in active_job_ids {
            if let Some(JobProgress {
                status: DaJobStatus::InProgress,
                sent_txs,
                ..
            }) = self.get_progress(&job_id)?
            {
                txids.extend(sent_txs.commit.into_iter().map(Txid::from_byte_array));
                txids.extend(sent_txs.reveal.into_iter().map(Txid::from_byte_array));
            }
        }

        Ok(txids)
    }

    /// Check if any job is in progress.
    pub async fn has_job_in_progress(&self) -> Result<bool> {
        let in_progress_jobs = self
            .ledger_db
            .get_job_ids_by_status(DaJobStatus::InProgress.as_u8())?;

        Ok(!in_progress_jobs.is_empty())
    }

    fn notify_new_status(&self, job_id: JobId, progress: &JobProgress) {
        let result = match &progress.status {
            DaJobStatus::Completed => {
                if let Some(last_tx) = progress.sent_txs.reveal.last() {
                    Ok(TxidWrapper(Txid::from_byte_array(*last_tx)))
                } else {
                    Err(JobServiceError::NoTransactionsFound(job_id).into())
                }
            }
            DaJobStatus::Cancelled => Err(JobServiceError::JobCancelled(job_id).into()),
            DaJobStatus::Failed { error } => {
                Err(JobServiceError::JobFailed(job_id, error.clone()).into())
            }
            DaJobStatus::Pending | DaJobStatus::InProgress => return,
        };

        if let Some(tx) = self.job_waiters.lock().remove(&job_id) {
            let _ = tx.send(result);
        }
    }

    pub(crate) fn insert_waiter(
        &self,
        job_id: JobId,
        waiter: oneshot::Sender<std::result::Result<TxidWrapper, BitcoinServiceError>>,
    ) {
        self.job_waiters.lock().insert(job_id, waiter);
    }

    pub(crate) fn recover_job(
        &self,
        job_id: Uuid,
    ) -> Result<oneshot::Receiver<std::result::Result<TxidWrapper, BitcoinServiceError>>> {
        let progress = self
            .get_progress(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))?;

        let (tx, rx) = oneshot::channel();

        match progress.status {
            DaJobStatus::Completed => {
                // Job already finished before we subscribed
                if let Some(last_tx) = progress.sent_txs.reveal.last() {
                    let _ = tx.send(Ok(TxidWrapper(Txid::from_byte_array(*last_tx))));
                } else {
                    let _ = tx.send(Err(JobServiceError::NoTransactionsFound(job_id).into()));
                }
            }
            DaJobStatus::Failed { error } => {
                // Job already failed
                let _ = tx.send(Err(JobServiceError::JobFailed(job_id, error).into()));
            }
            DaJobStatus::Cancelled => {
                // Job already cancelled
                let _ = tx.send(Err(JobServiceError::JobCancelled(job_id).into()));
            }
            DaJobStatus::Pending | DaJobStatus::InProgress => {
                // Job still running, register for notification
                self.insert_waiter(job_id, tx);
            }
        }

        Ok(rx)
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
            DaJobStatus::Pending | DaJobStatus::InProgress => {
                self.update_job_status(&mut progress, DaJobStatus::Cancelled)?;
                tracing::info!("Job {job_id} successfully cancelled");
                Ok(())
            }
            DaJobStatus::Completed | DaJobStatus::Cancelled | DaJobStatus::Failed { .. } => Err(
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
            DaJobStatus::Failed { .. } | DaJobStatus::Cancelled => {
                // Get original job and deserialize data
                let da_tx_request = self
                    .get_job_request(&job_id)?
                    .ok_or(JobServiceError::JobNotFound(job_id))?;

                let (tx, _rx) = oneshot::channel();
                // Create new job with same data
                let new_job_id = self.submit_job(da_tx_request, tx)?;
                tracing::info!("Job {job_id} retried as new job {new_job_id}");

                Ok(new_job_id)
            }
            DaJobStatus::Pending | DaJobStatus::InProgress | DaJobStatus::Completed => {
                Err(JobServiceError::JobRetryFailure(job_id, progress.status))
            }
        }
    }

    fn list_jobs(&self, filter: JobListFilter) -> Result<Vec<JobProgress>> {
        let limit = filter.limit.unwrap_or(25).min(100); // Defaults to 25, capped at 100
        let offset = filter.offset.unwrap_or(0);

        // Get job ids based on status filter
        let status_filter = filter.status.unwrap_or_default();

        let mut job_ids = Vec::new();
        for code in status_filter.to_job_status() {
            job_ids.extend(self.ledger_db.get_job_ids_by_status(code.as_u8())?);
        }
        job_ids.sort(); // sort chronologically by uuidv7

        // Apply pagination
        // TODO paginate at the db level. This should be sufficient for now as we take/skip on uuid before fetching job info
        let job_ids: Vec<_> = job_ids.into_iter().skip(offset).take(limit).collect();

        // Return (job, progress) per id
        let mut job_infos = Vec::new();
        for job_id in job_ids {
            if let Some(progress) = self.get_progress(&job_id)? {
                job_infos.push(progress);
            }
        }

        Ok(job_infos)
    }

    fn get_job_info(&self, job_id: JobId) -> Result<JobProgress> {
        self.get_progress(&job_id)?
            .ok_or(JobServiceError::JobNotFound(job_id))
    }
}
