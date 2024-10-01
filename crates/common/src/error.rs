use citrea_primitives::types::BlockNumber;

#[derive(Debug)]
pub enum SyncError {
    MissingL2(&'static str, BlockNumber, BlockNumber),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}
