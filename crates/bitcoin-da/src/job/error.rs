use sov_db::schema::types::da_jobs::JobId;
use thiserror::Error;

<<<<<<< HEAD
use crate::job::service::{JobId, JobStatus};

||||||| parent of d78b11900 (Convert from to db types)
use crate::job::service::JobId;

=======
>>>>>>> d78b11900 (Convert from to db types)
/// Job errors
#[derive(Error, Debug)]
pub enum JobServiceError {
    /// Job was not found
    #[error("Job not found: {0}")]
    JobNotFound(JobId),

    /// Job exceeded the timeout duration
    #[error("Job {0} timed out after {1} seconds")]
    JobTimeout(JobId, u64),

    /// Job completed in a corrupted state without transactions.
    #[error("Job {0} completed but no transactions found")]
    NoTransactionsFound(JobId),

    /// Failed to serialize or deserialize job data
    #[error("Job borsh serialization failed: {0}")]
    SerializationError(#[from] std::io::Error),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(#[from] anyhow::Error),

    /// Job execution failed
    #[error("Job {0} failed: {1}")]
    JobFailed(JobId, String),

    /// Job was cancelled before completion
    #[error("Job {0} was cancelled")]
    JobCancelled(JobId),

    /// Job cancellation failure
    #[error("Job {0} cannot be cancelled as it is in status: {1:?}")]
    JobCancellationFailure(JobId, JobStatus),

    /// Job retry failure
    #[error("Job {0} cannot be retried as it is in status: {1:?}")]
    JobRetryFailure(JobId, JobStatus),
}
