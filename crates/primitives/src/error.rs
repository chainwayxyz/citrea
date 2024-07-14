use sov_db::schema::types::BatchNumber;

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
