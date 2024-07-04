//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::guest::env;
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
        unimplemented!()
        // FIXME: env::read()
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        unimplemented!()
        // FIXME: env::commit(item);
    }
}
