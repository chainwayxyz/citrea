use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique job id using uuidv7 for ordering by creation time
pub type JobId = Uuid;

/// Job status representing the current state of transaction processing
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq)]
pub enum DaJobStatus {
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
        /// Error associated with the failure
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
pub struct SentChunks {
    /// Sent commit txids
    pub commit_txs: Vec<[u8; 32]>,
    /// Sent reveal txids
    pub reveal_txs: Vec<[u8; 32]>,
}

impl SentChunks {
    /// Number of sent commit/reveal pair
    pub fn count(&self) -> usize {
        self.reveal_txs.len()
    }

    /// Extend with sent commit and reveal chunks
    pub fn extend(&mut self, commits: Vec<[u8; 32]>, reveals: Vec<[u8; 32]>) {
        self.commit_txs.extend(commits);
        self.reveal_txs.extend(reveals);
    }

    /// Return a default SentChunk with empty vectors
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
    /// Partially sent commit/reveal chunks for partial sending and recovery
    pub sent_chunks: SentChunks,
    /// Last update timestamp
    pub last_updated: u64,
}

impl JobProgress {
    /// Creates a new `JobProgress`
    pub fn new(job_id: JobId, last_updated: u64) -> Self {
        Self {
            job_id,
            status: DaJobStatus::Pending,
            sent_chunks: SentChunks::new(),
            last_updated,
        }
    }
}

/// DA Job representing a transaction to be sent to the DA layer
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Job {
    /// Job id as uuidv7
    pub id: JobId,
    /// Raw job data (serialized RawTxData)
    pub data: Vec<u8>,
    /// Time of job creation
    pub created_at: u64,
}

impl Job {
    /// Create a new job with the given serialized data
    pub fn new(id: JobId, data: Vec<u8>, created_at: u64) -> Self {
        Self {
            id,
            data,
            created_at,
        }
    }
}
