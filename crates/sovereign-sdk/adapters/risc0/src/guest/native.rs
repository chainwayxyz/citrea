//! This module implements the `ZkvmGuest` trait for the RISC0 VM.

use std::io::Cursor;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::zk::ZkvmGuest;

#[derive(Default)]
struct Hints {
    cursor: Cursor<Vec<u8>>,
}

impl Hints {
    pub fn with_hints(hints: Vec<u8>) -> Self {
        Hints {
            cursor: Cursor::new(hints),
        }
    }
}

/// A guest for the RISC0 VM. Implements the `ZkvmGuest` trait
/// using interior mutability to test the functionality.
#[derive(Default)]
pub struct Risc0Guest {
    hints: std::sync::Mutex<Hints>,
    // commits: std::sync::Mutex<Vec<u32>>,
}

impl Risc0Guest {
    /// Constructs a new Risc0 Guest
    pub fn new() -> Self {
        Self::default()
    }

    /// Constructs a new Risc0 Guest with the provided hints.
    pub fn with_hints(hints: Vec<u8>) -> Self {
        Self {
            hints: std::sync::Mutex::new(Hints::with_hints(hints)),
            // commits: Default::default(),
        }
    }
}

impl ZkvmGuest for Risc0Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        let mut hints = self.hints.lock().unwrap();
        let cursor = &mut hints.cursor;
        // deserialize
        BorshDeserialize::deserialize_reader(&mut *cursor).unwrap()
    }

    fn commit<T: BorshSerialize>(&self, _item: &T) {
        unimplemented!("commitment never used in a test code")
        // self.commits.lock().unwrap().extend_from_slice(
        //     &risc0_zkvm::serde::to_vec(item).expect("Serialization to vec is infallible"),
        // );
    }
}
