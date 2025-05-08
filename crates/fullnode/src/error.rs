use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Commitment index {0} is missing for proof")]
    SequencerCommitmentMissingForProof(u32),
    #[error("Batch proof output last_l1_hash_on_bitcoin_light_client_contract isn't known")]
    UnknownL1Hash,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
