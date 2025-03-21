//! This module implements the `ZkvmGuest` trait for the SP1 VM.

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::zk::ZkvmGuest;
use sp1_zkvm::io;

#[cfg(feature = "native")]
mod native;

#[cfg(feature = "native")]
pub use native::VerifyingKey;

#[cfg(not(feature = "native"))]
mod zk;

/// A guest for the SP1 VM. Implements the `ZkvmGuest` trait
///  in terms of SP1's io::read and io::write functions.
#[derive(Default)]
pub struct SP1Guest {}

impl SP1Guest {
    /// Constructs a new SP1Guest
    pub fn new() -> Self {
        Self::default()
    }
}

impl ZkvmGuest for SP1Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        let buf = io::read_vec();
        T::try_from_slice(&buf).expect("Failed to deserialize input from host")
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        io::commit_slice(&buf);
    }

    fn verify_with_assumptions(_journal: &[u8], _code_commitment: &Self::CodeCommitment) {}
}
