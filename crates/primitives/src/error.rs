use sov_db::schema::types::BatchNumber;
use sov_stf_runner::ProverServiceError;

#[derive(Debug)]
pub enum SyncError {
    MissingL2(&'static str, BatchNumber, BatchNumber),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}

impl From<ProverServiceError> for SyncError {
    fn from(e: ProverServiceError) -> Self {
        Self::Error(e.into())
    }
}
