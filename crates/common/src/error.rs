use citrea_primitives::types::BlockNumber;

#[derive(Debug)]
pub enum SyncError {
    MissingL2(&'static str, BlockNumber, BlockNumber),
    // Should not retry in this case
    SequencerCommitmentNotFound([u8; 32]),
    SequencerCommitmentWithIndexNotFound(u32),
    SequencerCommitmentMissingForProof(u32),
    UnknownL1Hash,
    Error(anyhow::Error),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}
