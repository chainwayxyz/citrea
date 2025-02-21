use borsh::{BorshDeserialize, BorshSerialize};

/// A [`Vec`]-based implementation of [`Witness`] with no special logic.
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
    next_idx: usize,
    hints: Vec<Vec<u8>>,
}

impl Witness {
    /// Add a serializable hint
    pub fn add_hint<T: BorshSerialize>(&mut self, hint: &T) {
        self.hints.push(borsh::to_vec(hint).unwrap())
    }

    /// Get the next deserializable hint
    pub fn get_hint<T: BorshDeserialize>(&mut self) -> T {
        let idx = self.next_idx;
        self.next_idx += 1;
        T::deserialize_reader(&mut std::io::Cursor::new(&self.hints[idx]))
            .expect("Hint deserialization should never fail")
    }
}
