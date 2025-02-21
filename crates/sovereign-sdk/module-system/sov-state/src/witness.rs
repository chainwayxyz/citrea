use std::{collections::VecDeque, mem};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_modules_core::Witness;
use sov_rollup_interface::RefCount;

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
#[derive(Default, BorshDeserialize, BorshSerialize, Debug, Serialize, Deserialize)]
pub struct ArrayWitness {
    // keeping this field for backwards compatibility
    next_idx: usize,
    hints: VecDeque<RefCount<[u8]>>,
}

// Witness type is very complexly tied to different trait types, and it is hard to make it
// not require Send + Sync. For native, RefCount = Arc, and it is already Send + Sync.
// For zk RefCount = Rc, but zk is single-threaded, hence this does the trick.
#[cfg(not(feature = "native"))]
unsafe impl Send for ArrayWitness {}
#[cfg(not(feature = "native"))]
unsafe impl Sync for ArrayWitness {}

impl Witness for ArrayWitness {
    fn add_hint_raw(&mut self, hint: RefCount<[u8]>) {
        self.hints.push_back(hint);
    }

    fn get_hint_raw(&mut self) -> RefCount<[u8]> {
        self.hints.pop_front().expect("Not enough hints in the witness")
    }

    fn merge(&mut self, rhs: &mut Self) {
        self.hints.extend(mem::take(&mut rhs.hints))
    }
}
