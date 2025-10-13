use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique job id using uuidv7 for ordering by creation time
pub type JobId = Uuid;

/// Job status representing the current state of transaction processing
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq)]
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
        /// Error associated with the failure
        error: String,
    },
}

/// Track sent chunk for partial sending and recovery
#[derive(Debug, Default, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SentChunks {
    /// Sent commit txs (serialized bitcoin::Transaction)
    pub commit_txs: Vec<Vec<u8>>,
    /// Sent reveal txs (serialized bitcoin::Transaction)
    pub reveal_txs: Vec<Vec<u8>>,
}

impl SentChunks {
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
    pub status: JobStatus,
    /// Partially sent commit/reveal chunks for partial sending and recovery
    pub sent_chunks: SentChunks,
    /// Last update timestamp
    pub last_updated: u64,
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
