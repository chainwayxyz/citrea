use citrea_primitives::types::BlockNumber;
use sov_db::schema::types::L2HeightAndIndex;

#[derive(Debug)]
pub enum SyncError {
    MissingL2(&'static str, BlockNumber, BlockNumber),
    // Should not retry in this case
    SequencerCommitmentNotFound([u8; 32]),
    SequencerCommitmentWithIndexNotFound(u32),
    ProvenHeightExceedsCommittedHeight(L2HeightAndIndex, L2HeightAndIndex),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}
