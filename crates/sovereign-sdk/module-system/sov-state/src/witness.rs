use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

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
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ArrayWitness {
    next_idx: AtomicUsize,
    hints: Mutex<Vec<Vec<u8>>>,
}

impl Witness for ArrayWitness {
    fn add_hint<T: BorshSerialize>(&self, hint: T) {
        self.hints
            .lock()
            .unwrap()
            .push(borsh::to_vec(&hint).unwrap());
    }

    fn get_hint<T: BorshDeserialize>(&self) -> T {
        let idx = self
            .next_idx
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let hints_lock = self.hints.lock().unwrap();
        T::deserialize(&mut hints_lock[idx].as_slice())
            .expect("Hint deserialization should never fail")
    }

    fn merge(&self, rhs: &Self) {
        let rhs_next_idx = rhs.next_idx.load(std::sync::atomic::Ordering::SeqCst);
        let mut lhs_hints_lock = self.hints.lock().unwrap();
        let mut rhs_hints_lock = rhs.hints.lock().unwrap();
        lhs_hints_lock.extend(rhs_hints_lock.drain(rhs_next_idx..));
    }
}

impl BorshSerialize for ArrayWitness {
    fn serialize<W: std::io::prelude::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        borsh::BorshSerialize::serialize(
            &self.next_idx.load(std::sync::atomic::Ordering::Relaxed),
            writer,
        )?;
        let hints = self.hints.lock().unwrap();
        borsh::BorshSerialize::serialize(&*hints, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for ArrayWitness {
    fn deserialize_reader<R: std::io::prelude::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            next_idx: AtomicUsize::new(borsh::BorshDeserialize::deserialize_reader(reader)?),
            hints: Mutex::new(borsh::BorshDeserialize::deserialize_reader(reader)?),
        })
    }
}
