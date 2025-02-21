//! Runtime witness definitions.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_rollup_interface::RefCount;

/// A witness is a value produced during native execution that is then used by
/// the zkVM circuit to produce proofs.
///
/// Witnesses are typically used to abstract away storage access from inside the
/// zkVM. For every read operation performed by the native code, a hint can be
/// added and the zkVM circuit can then read the same hint. Hints are replayed
/// to [`Witness::get_hint`] in the same order
/// they were added via [`Witness::add_hint`].
// TODO: Refactor witness trait so it only require Serialize / Deserialize
//   https://github.com/Sovereign-Labs/sovereign-sdk/issues/263
pub trait Witness:
    Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned
{
    /// Adds a serializable "hint" to the witness value, which can be later
    /// read by the zkVM circuit.
    ///
    /// This method **SHOULD** only be called from the native execution
    /// environment.
    fn add_hint<T: BorshSerialize>(&mut self, hint: &T) {
        let hint_serialized = borsh::to_vec(hint).unwrap();
        self.add_hint_raw(RefCount::from(hint_serialized));
    }

    /// Adds a raw "hint" to the witness value, which can be later
    /// read by the zkVM circuit.
    ///
    /// This method **SHOULD** only be called from the native execution
    /// environment.
    fn add_hint_raw(&mut self, hint: RefCount<[u8]>);

    /// Retrieves a "hint" from the witness value.
    fn get_hint<T: BorshDeserialize>(&mut self) -> T {
        let hint = self.get_hint_raw();
        borsh::from_slice(&hint).unwrap()
    }

    /// Retrieves a raw "hint" from the witness value.
    fn get_hint_raw(&mut self) -> RefCount<[u8]>;

    /// Adds all hints from `rhs` to `self`.
    fn merge(&mut self, rhs: &mut Self);
}
