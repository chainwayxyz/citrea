//! Error types for the fullnode crate
//!
//! This module defines various error types that can occur during fullnode operations,
//! particularly around proof verification and commitment processing.

use thiserror::Error;

/// Errors that can occur during proof verification and processing
#[derive(Error, Debug)]
pub enum ProofError {
    /// Error when a sequencer commitment at the specified index is missing for proof verification
    #[error("Commitment index {0} is missing for proof")]
    SequencerCommitmentMissingForProof(u32),
    /// Error when a proof references an unknown L1 hash
    #[error("Batch proof output last_l1_hash_on_bitcoin_light_client_contract isn't known")]
    UnknownL1Hash,
    /// Error when the pre-state root in the proof doesn't match the expected value
    #[error("Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{0} but got 0x{1}. Skipping proof.")]
    PreStateRootMismatch(String, String),
    /// Error when the sequencer commitment hash doesn't match the expected value
    #[error("Proof verification: For a known and verified sequencer commitment. Hash mismatch - expected 0x{0} but got 0x{1}. Skipping proof.")]
    SequencerCommitmentHashMismatch(String, String),
    /// Other general errors that may occur during proof processing
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Errors that can occur during commitment processing
#[derive(Error, Debug)]
pub enum CommitmentError {
    /// Error when the merkle root of a commitment doesn't match the expected value
    #[error("Commitment merkle root mismatch: {0}")]
    MerkleRootMismatch(String),
    /// Other general errors that may occur during commitment processing
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Errors that require the node to halt L1 processing
#[derive(Debug, Error)]
pub enum HaltingError {
    /// Critical proof errors that require halting
    #[error("Halting Proof error: {0}")]
    Proof(#[from] ProofError),
    /// Critical commitment errors that require halting
    #[error("Halting Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

/// Errors that allow the node to continue processing (can be skipped)
#[derive(Debug, Error)]
pub enum SkippableError {
    /// Non-critical proof errors that can be skipped
    #[error("Skippable Proof error: {0}")]
    Proof(#[from] ProofError),
    /// Non-critical commitment errors that can be skipped
    #[error("Skippable Commitment error: {0}")]
    Commitment(#[from] CommitmentError),
}

/// Top-level error type encompassing all processing errors
#[derive(Debug, Error)]
pub enum ProcessingError {
    /// Errors that require halting L1 syncing
    #[error("Halting error: {0}")]
    HaltingError(#[from] HaltingError),
    /// Errors that can be skipped
    #[error("Skippable error: {0}")]
    SkippableError(#[from] SkippableError),
    /// Other general errors during processing
    #[error("Processing error: {0}")]
    Other(#[from] anyhow::Error),
}
