use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique job id using uuidv7 for ordering by creation time
pub type JobId = Uuid;

/// Job status representing the current state of transaction processing
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum DaJobStatus {
    /// Job is queued and waiting to be processed.
    Pending,
    /// Job is in progress. None or some its txs have been sent to DA.
    InProgress,
    /// Job completed successfully. All its txs have been sent to DA.
    Completed,
    /// Job was cancelled before completion.
    Cancelled,
    /// Job failed with error.
    Failed {
        /// Error associated with the failure.
        error: String,
    },
}

impl DaJobStatus {
    /// u8 representation of `DaJobStatus`
    pub fn as_u8(&self) -> u8 {
        match self {
            DaJobStatus::Pending => 0,
            DaJobStatus::InProgress => 1,
            DaJobStatus::Completed => 2,
            DaJobStatus::Cancelled => 3,
            DaJobStatus::Failed { .. } => 4,
        }
    }
}

/// Track sent chunk for partial sending and recovery
#[derive(Debug, Default, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SentTxs {
    /// Sent commit txids
    pub commit: Vec<[u8; 32]>,
    /// Sent reveal txids
    pub reveal: Vec<[u8; 32]>,
}

impl SentTxs {
    /// Number of sent commit/reveal pair
    pub fn count(&self) -> usize {
        self.reveal.len()
    }

    /// Extend with sent commit and reveal chunks
    pub fn extend(&mut self, commits: Vec<[u8; 32]>, reveals: Vec<[u8; 32]>) {
        self.commit.extend(commits);
        self.reveal.extend(reveals);
    }

    /// Return a default SentTxs with empty vectors
    pub fn new() -> Self {
        Self::default()
    }
}

/// Tracks progress of a job including sent transactions for recovery.
///
/// This state is persisted to the database and updated as transactions
/// are sent to bitcoin da.
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct JobProgress {
    /// Job id as uuidv7
    pub job_id: JobId,
    /// Current job status
    pub status: DaJobStatus,
    /// Sent commit/reveal txs for tracking, partial sending and recovery
    pub sent_txs: SentTxs,
    /// Last update timestamp
    pub last_updated: u64,
    /// Last recoverable error message
    pub last_error: Option<String>,
}

impl JobProgress {
    /// Creates a new `JobProgress`
    pub fn new(job_id: JobId, last_updated: u64) -> Self {
        Self {
            job_id,
            status: DaJobStatus::Pending,
            sent_txs: SentTxs::new(),
            last_updated,
            last_error: None,
        }
    }
}
