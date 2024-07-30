#[derive(Debug)]
pub enum SyncError {
    MissingL2(&'static str, u64, u64),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}
