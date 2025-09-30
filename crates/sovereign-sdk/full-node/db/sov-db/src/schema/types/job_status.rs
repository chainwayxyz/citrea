use std::fmt::Debug;

use serde::{Deserialize, Serialize};

/// The on-disk format for a job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JobStatus {
    /// Proving
    Proving,
    /// Sending to DA
    Sending,
    /// Finished
    Finished,
}
