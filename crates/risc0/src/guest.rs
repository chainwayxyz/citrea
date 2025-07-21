//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write;
use risc0_zkvm::{Digest, VerifierContext};
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

use crate::receipt_from_proof;

/// A guest for the RISC0 VM. Implements the `ZkvmGuest` trait
///  in terms of Risc0's env::read and env::commit functions.
#[derive(Default)]
pub struct Risc0Guest {}

impl Risc0Guest {
    /// Constructs a new Risc0 Guest
    pub fn new() -> Self {
        Self::default()
    }
}

impl ZkvmGuest for Risc0Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        let mut reader = env::stdin();
        // deserialize
        BorshDeserialize::deserialize_reader(&mut reader)
            .expect("Failed to deserialize input from host")
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        // use risc0_zkvm::guest::env::Write as _;
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        let mut journal = env::journal();
        journal.write_slice(&buf);
    }

    fn verify_with_assumptions(journal: &[u8], code_commitment: &Self::CodeCommitment) {
        env::verify(*code_commitment, journal)
            .expect("Assumption API verify error should be infallible")
    }
}

impl Zkvm for Risc0Guest {
    type CodeCommitment = Digest;

    type Error = Risc0GuestError;

    /// Unlike other verify functions in this module, this function accepts the full proof.
    /// Returns Ok if proof passes and Err otherwise.
    /// The reason this function exists is that efficient proof verification inside the
    /// guest cannot have the proof fail. This uses host side API for proof verification
    /// so it can show a proof fails.
    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
        allow_dev_mode: bool,
    ) -> Result<(), Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)
            .map_err(|_| Risc0GuestError::FailedToDeserialize)?;

        receipt
            .verify_with_context(
                &VerifierContext::default().with_dev_mode(allow_dev_mode),
                *code_commitment,
            )
            .map_err(|_| Risc0GuestError::ProofVerificationFailed)
    }

    fn extract_raw_output(serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)
            .map_err(|_| Risc0GuestError::FailedToDeserialize)?;
        Ok(receipt.journal.bytes)
    }

    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> Result<T, Self::Error> {
        T::try_from_slice(journal).map_err(|_| Risc0GuestError::FailedToDeserialize)
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
        allow_dev_mode: bool,
    ) -> Result<T, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)
            .map_err(|_| Risc0GuestError::FailedToDeserialize)?;

        receipt
            .verify_with_context(
                &VerifierContext::default().with_dev_mode(allow_dev_mode),
                *code_commitment,
            )
            .map_err(|_| Risc0GuestError::ProofVerificationFailed)?;

        T::try_from_slice(&receipt.journal.bytes).map_err(|_| Risc0GuestError::FailedToDeserialize)
    }
}

#[derive(Debug)]
/// Error type for Risc0Guest
pub enum Risc0GuestError {
    /// Failed to deserialize something
    FailedToDeserialize,
    /// Proof verification failed
    ProofVerificationFailed,
}
