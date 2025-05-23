use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Commitment index {0} is missing for proof")]
    SequencerCommitmentMissingForProof(u32),
    #[error("Batch proof output last_l1_hash_on_bitcoin_light_client_contract isn't known")]
    UnknownL1Hash,
    #[error("Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{0} but got 0x{1}. Skipping proof.")]
    PreStateRootMismatch(String, String),
    #[error("Proof verification: For a known and verified sequencer commitment. Hash mismatch - expected 0x{0} but got 0x{1}. Skipping proof.")]
    SequencerCommitmentHashMismatch(String, String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Commitment merkle root mismatch: {0}")]
    MerkleRootMismatch(String),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum HaltingError {
    #[error("Halting Proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("Halting Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

#[derive(Debug, Error)]
pub enum SkippableError {
    #[error("Skippable Proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("Skippable Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

#[derive(Debug, Error)]
pub enum ProcessingError {
    #[error("Halting error: {0}")]
    HaltingError(#[from] HaltingError),
    #[error("Skippable error: {0}")]
    SkippableError(#[from] SkippableError),
    #[error("Processing error: {0}")]
    Other(#[from] anyhow::Error),
}
