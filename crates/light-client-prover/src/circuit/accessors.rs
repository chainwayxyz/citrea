/// In this module we define the accessors for the different type of data we'll be using in the circuit.
/// We don't use the StateMap or Module system here, as our keys are all hashes of different things, we
/// don't want the serialization overhead.
use sov_modules_api::{StateReaderAndWriter, WorkingSet};
use sov_modules_core::{Prefix, Storage, StorageKey, StorageValue};

pub struct BlockHashAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BlockHashAccessor<S> {
    const PREFIX: u8 = 98u8; // lowercase b

    pub fn exists(hash: [u8; 32], working_set: &mut WorkingSet<S>) -> bool {
        // use `StateKey::singleton` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key.copy_from_slice(&[Self::PREFIX]);
        key[1..].copy_from_slice(&hash);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton(&p);

        working_set.get(&key).is_some()
    }

    pub fn insert(hash: [u8; 32], working_set: &mut WorkingSet<S>) {
        // use `StateKey::singleton` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key.copy_from_slice(&[Self::PREFIX]);
        key[1..].copy_from_slice(&hash);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);
        // we insert an empty value, as we only care about the key
        let value: StorageValue = (vec![]).into();
        working_set.set(&key, value);
    }
}

pub struct ChunkAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> ChunkAccessor<S> {
    const PREFIX: u8 = 99u8; // lowercase c

    pub fn get(wtxid: [u8; 32], working_set: &mut WorkingSet<S>) -> Option<Vec<u8>> {
        // use `StateKey::singleton` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key.copy_from_slice(&[Self::PREFIX]);
        key[1..].copy_from_slice(&wtxid);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton(&p);

        working_set.get(&key).map(|v| v.value().to_vec())
    }

    /// Rerturns body of the chunk if it exists
    /// None if it doesn't
    pub fn insert(wtxid: [u8; 32], body: Vec<u8>, working_set: &mut WorkingSet<S>) {
        // use `StateKey::singleton` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key.copy_from_slice(&[Self::PREFIX]);
        key[1..].copy_from_slice(&wtxid);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        let value: StorageValue = body.into();

        working_set.set(&key, value);
    }
}

// TODO: write raw accessor tests with JMT
// and prover storage manager
#[cfg(test)]
mod tests {}
