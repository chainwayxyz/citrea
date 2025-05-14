//! Defines versioned witness types to be used.

use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

/// A [`VecDeque`]-based implementation of [`Witness`] with no special logic.
///
/// # Example
///
/// ```
/// use sov_state::{ArrayWitness, Witness};
///
/// let mut witness = ArrayWitness::default();
///
/// witness.add_hint(&1u64);
/// witness.add_hint(&2u64);
///
/// assert_eq!(witness.get_hint::<u64>(), 1u64);
/// assert_eq!(witness.get_hint::<u64>(), 2u64);
/// ```
#[derive(Default, BorshDeserialize, BorshSerialize, Debug)]
pub struct Witness {
    hints: VecDeque<Vec<u8>>,
}

impl Witness {
    /// Add a serializable hint
    pub fn add_hint<T: BorshSerialize>(&mut self, hint: &T) {
        self.hints.push_back(borsh::to_vec(hint).unwrap())
    }

    /// Get the next deserializable hint
    pub fn get_hint<T: BorshDeserialize>(&mut self) -> T {
        let hint = self.hints.pop_front().expect("No more hints left");
        T::deserialize_reader(&mut hint.as_slice()).expect("Hint deserialization should never fail")
    }

    /// Number of hints left
    pub fn remaining(&self) -> usize {
        self.hints.len()
    }

    #[cfg(feature = "testing")]
    /// Get the hints
    pub fn get_hints(&self) -> VecDeque<Vec<u8>> {
        self.hints.clone()
    }
}

#[cfg(feature = "testing")]
impl From<VecDeque<Vec<u8>>> for Witness {
    fn from(hints: VecDeque<Vec<u8>>) -> Self {
        Self { hints }
    }
}
