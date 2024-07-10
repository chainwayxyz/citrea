//! This module implements the `ZkvmGuest` trait for the RISC0 VM.

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::zk::ZkvmGuest;

#[derive(Default)]
struct Hints {
    values: Vec<u32>,
    position: usize,
}

impl Hints {
    pub fn with_hints(hints: Vec<u32>) -> Self {
        Hints {
            values: hints,
            position: 0,
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
    pub fn with_hints(hints: Vec<u32>) -> Self {
        Self {
            hints: std::sync::Mutex::new(Hints::with_hints(hints)),
            // commits: Default::default(),
        }
    }
}

impl ZkvmGuest for Risc0Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        let mut hints = self.hints.lock().unwrap();
        let hints = &mut *hints;
        let pos = &mut hints.position;
        let env = &hints.values;
        // read len(u64) in LE
        let len_buf = &env[*pos..*pos + 2];
        let len_bytes = bytemuck::cast_slice(len_buf);
        let len_bytes: [u8; 8] = len_bytes.try_into().expect("Exactly 4 bytes");
        let len = u64::from_le_bytes(len_bytes) as usize;
        *pos += 2;
        // read buf
        let buf = &env[*pos..*pos + len];
        let buf: &[u8] = bytemuck::cast_slice(buf);
        *pos += len;
        // deserialize
        BorshDeserialize::deserialize(&mut &*buf).unwrap()
    }

    fn commit<T: BorshSerialize>(&self, _item: &T) {
        unimplemented!("commitment never used in a test code")
        // self.commits.lock().unwrap().extend_from_slice(
        //     &risc0_zkvm::serde::to_vec(item).expect("Serialization to vec is infallible"),
        // );
    }
}
