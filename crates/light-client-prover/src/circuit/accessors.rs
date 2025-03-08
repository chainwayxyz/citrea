/// In this module we define the accessors for the different type of data we'll be using in the circuit.
/// We don't use the StateMap or Module system here, as our keys are all hashes of different things, we
/// don't want the serialization overhead.
use sov_modules_api::{StateReaderAndWriter, WorkingSet};
use sov_modules_core::{Prefix, Storage, StorageKey, StorageValue};
use sov_rollup_interface::RefCount;

pub struct BlockHashAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BlockHashAccessor<S> {
    const PREFIX: u8 = b'b';

    pub fn exists(hash: [u8; 32], working_set: &mut WorkingSet<S>) -> bool {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&hash);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        working_set.get(&key).is_some()
    }

    pub fn insert(hash: [u8; 32], working_set: &mut WorkingSet<S>) {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
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
    const PREFIX: u8 = b'c';

    /// Returns body of the chunk if it exists
    pub fn get(wtxid: [u8; 32], working_set: &mut WorkingSet<S>) -> Option<RefCount<[u8]>> {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&wtxid);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        working_set.get(&key).map(|v| v.into())
    }

    /// Insert a new chunk to the LCP state
    pub fn insert(wtxid: [u8; 32], body: Vec<u8>, working_set: &mut WorkingSet<S>) {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&wtxid);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        let value: StorageValue = body.into();

        working_set.set(&key, value);
    }
}

#[cfg(test)]
mod tests {
    use sov_modules_api::WorkingSet;
    use sov_modules_core::Storage;
    use sov_prover_storage_manager::{new_orphan_storage, ProverStorage};
    use sov_rollup_interface::witness::Witness;

    use super::{BlockHashAccessor, ChunkAccessor};

    #[test]
    fn test_block_hash_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        BlockHashAccessor::<ProverStorage>::insert([1; 32], &mut working_set);

        assert!(BlockHashAccessor::<ProverStorage>::exists(
            [1; 32],
            &mut working_set
        ));

        assert!(!BlockHashAccessor::<ProverStorage>::exists(
            [2; 32],
            &mut working_set
        ));

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        // sanity check
        // why 5?
        // 1 exists value for [2; 32] (None)
        // 1 non-existence proof for [2; 32] -> commit
        // 1 initial root -> commit
        // 1 update proof -> commit
        // 1 final root
        assert_eq!(witness.remaining(), 5);

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert!(BlockHashAccessor::<ProverStorage>::exists(
            [1; 32],
            &mut working_set
        ));

        assert!(!BlockHashAccessor::<ProverStorage>::exists(
            [2; 32],
            &mut working_set
        ));
    }

    #[test]
    fn test_chunk_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        ChunkAccessor::<ProverStorage>::insert([1; 32], vec![12; 150], &mut working_set);

        assert_eq!(
            ChunkAccessor::<ProverStorage>::get([1; 32], &mut working_set)
                .unwrap()
                .to_vec(),
            vec![12; 150]
        );

        assert!(ChunkAccessor::<ProverStorage>::get([2; 32], &mut working_set).is_none());

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            ChunkAccessor::<ProverStorage>::get([1; 32], &mut working_set)
                .unwrap()
                .to_vec(),
            vec![12; 150]
        );

        assert!(ChunkAccessor::<ProverStorage>::get([2; 32], &mut working_set).is_none());
    }
}
