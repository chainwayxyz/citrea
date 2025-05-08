#[derive(Debug)]
pub enum ProofError {
    SequencerCommitmentMissingForProof(u32),
    UnknownL1Hash,
    Error(anyhow::Error),
}

impl From<anyhow::Error> for ProofError {
    fn from(e: anyhow::Error) -> Self {
        Self::Error(e)
    }
}
