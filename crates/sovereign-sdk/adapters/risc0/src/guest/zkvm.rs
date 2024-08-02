//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::env::Write;
use sov_rollup_interface::zk::ZkvmGuest;

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
        BorshDeserialize::deserialize_reader(&mut reader).expect("Failed to deserialize input from host")
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        // use risc0_zkvm::guest::env::Write as _;
        let buf = borsh::to_vec(item).expect("Serialization to vec is infallible");
        let mut journal = env::journal();
        journal.write_slice(&buf);
    }
}
