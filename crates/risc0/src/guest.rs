//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write;
use risc0_zkvm::Receipt;
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

use crate::Risc0MethodId;

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
}

impl Zkvm for Risc0Guest {
    type CodeCommitment = Risc0MethodId;

    type Error = Risc0GuestError;

    fn verify(journal: &[u8], code_commitment: &Self::CodeCommitment) -> Result<(), Self::Error> {
        env::verify(code_commitment.0, journal)
            .expect("Guest side verification error should be Infallible");
        Ok(())
    }

    fn extract_raw_output(serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)
            .map_err(|_| Risc0GuestError::FailedToDeserialize)?;
        Ok(receipt.journal.bytes)
    }

    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> Result<T, Self::Error> {
        T::try_from_slice(journal).map_err(|_| Risc0GuestError::FailedToDeserialize)
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        journal: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        env::verify(code_commitment.0, journal)
            .expect("Guest side verification error should be Infallible");
        T::try_from_slice(journal).map_err(|_| Risc0GuestError::FailedToDeserialize)
    }
}

#[derive(Debug)]
/// Error type for Risc0Guest
pub enum Risc0GuestError {
    /// Failed to deserialize something
    FailedToDeserialize,
}
