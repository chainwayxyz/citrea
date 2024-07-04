//! This module implements the `ZkvmGuest` trait for the RISC0 VM.

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::serde::WordRead;
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

impl WordRead for Hints {
    fn read_words(&mut self, words: &mut [u32]) -> risc0_zkvm::serde::Result<()> {
        if let Some(slice) = self.values.get(self.position..self.position + words.len()) {
            words.copy_from_slice(slice);
            self.position += words.len();
            Ok(())
        } else {
            Err(risc0_zkvm::serde::Error::DeserializeUnexpectedEnd)
        }
    }

    fn read_padded_bytes(&mut self, bytes: &mut [u8]) -> risc0_zkvm::serde::Result<()> {
        use risc0_zkvm::align_up;
        use risc0_zkvm_platform::WORD_SIZE;

        let remaining_bytes: &[u8] = bytemuck::cast_slice(&self.values[self.position..]);
        if bytes.len() > remaining_bytes.len() {
            return Err(risc0_zkvm::serde::Error::DeserializeUnexpectedEnd);
        }
        bytes.copy_from_slice(&remaining_bytes[..bytes.len()]);
        self.position += align_up(bytes.len(), WORD_SIZE) / WORD_SIZE;
        Ok(())
    }
}

/// A guest for the RISC0 VM. Implements the `ZkvmGuest` trait
/// using interior mutability to test the functionality.
#[derive(Default)]
pub struct Risc0Guest {
    hints: std::sync::Mutex<Hints>,
    commits: std::sync::Mutex<Vec<u32>>,
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
            commits: Default::default(),
        }
    }
}

impl ZkvmGuest for Risc0Guest {
    fn read_from_host<T: BorshDeserialize>(&self) -> T {
        unimplemented!("read_from_host")
        // let mut hints = self.hints.lock().unwrap();
        // let mut hints = hints.deref_mut();
        // T::deserialize(&mut Deserializer::new(&mut hints)).unwrap()
    }

    fn commit<T: BorshSerialize>(&self, item: &T) {
        unimplemented!("commit")
        // self.commits.lock().unwrap().extend_from_slice(
        //     &risc0_zkvm::serde::to_vec(item).expect("Serialization to vec is infallible"),
        // );
    }
}
