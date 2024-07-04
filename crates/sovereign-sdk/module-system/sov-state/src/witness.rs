use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::Witness;

/// A [`Vec`]-based implementation of [`Witness`] with no special logic.
///
/// # Example
///
/// ```
/// use sov_state::{ArrayWitness, Witness};
///
/// let witness = ArrayWitness::default();
///
/// witness.add_hint(1u64);
/// witness.add_hint(2u64);
///
/// assert_eq!(witness.get_hint::<u64>(), 1u64);
/// assert_eq!(witness.get_hint::<u64>(), 2u64);
/// ```
#[derive(Default, BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct ArrayWitness {
    next_idx: usize,
    hints: Vec<Vec<u8>>,
}

impl Witness for ArrayWitness {
    fn add_hint<T: BorshSerialize>(&mut self, hint: T) {
        self.hints.push(hint.try_to_vec().unwrap())
    }

    fn get_hint<T: BorshDeserialize>(&mut self) -> T {
        let idx = self.next_idx;
        self.next_idx += 1;
        T::deserialize_reader(&mut std::io::Cursor::new(&self.hints[idx]))
            .expect("Hint deserialization should never fail")
    }

    fn merge(&mut self, rhs: &mut Self) {
        let rhs_next_idx = rhs.next_idx;
        let lhs_hints_lock = &mut self.hints;
        let rhs_hints_lock = &mut rhs.hints;
        lhs_hints_lock.extend(rhs_hints_lock.drain(rhs_next_idx..))
    }
}
