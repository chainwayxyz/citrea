/// In this module we define the accessors for the different type of data we'll be using in the circuit.
/// We don't use the StateMap or Module system here, as our keys are all hashes of different things, we
/// don't want the serialization overhead.
use sov_modules_api::{StateReaderAndWriter, WorkingSet};
use sov_modules_core::{Prefix, Storage, StorageKey, StorageValue};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::zk::light_client_proof::output::VerifiedStateTransitionForSequencerCommitmentIndex;
use sov_rollup_interface::RefCount;

use super::InitialBatchProofMethodIds;

pub type BatchProofMethodIds = Vec<(u64, [u32; 8])>;

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

pub struct SequencerCommitmentAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> SequencerCommitmentAccessor<S> {
    const PREFIX: u8 = b's';

    fn key(index: u32) -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 5]; // 1 prefix + 4 bytes

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&index.to_be_bytes());

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Returns sequencer commitment if it exists
    pub fn get(index: u32, working_set: &mut WorkingSet<S>) -> Option<SequencerCommitment> {
        let key = Self::key(index);

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes).expect("Commitment deserialization should not fail")
        })
    }

    /// Insert a new sequencer commitment to the LCP state
    pub fn insert(index: u32, commitment: SequencerCommitment, working_set: &mut WorkingSet<S>) {
        let key = Self::key(index);
        let value: StorageValue = borsh::to_vec(&commitment)
            .expect("Commitment serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

pub struct VerifiedStateTransitionForSequencerCommitmentIndexAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> VerifiedStateTransitionForSequencerCommitmentIndexAccessor<S> {
    const PREFIX: u8 = b'u';

    fn key(index: u32) -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 5]; // 1 prefix + 4 bytes

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&index.to_be_bytes());

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Returns batch proof info if it exists
    pub fn get(
        index: u32,
        working_set: &mut WorkingSet<S>,
    ) -> Option<VerifiedStateTransitionForSequencerCommitmentIndex> {
        let key = Self::key(index);

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes).expect("Verified State Transition For Sequencer Commitment Index deserialization should not fail")
        })
    }

    /// Insert a new batch proof info to the LCP state
    pub fn insert(
        index: u32,
        sequencer_commitment_info: VerifiedStateTransitionForSequencerCommitmentIndex,
        working_set: &mut WorkingSet<S>,
    ) {
        let key = Self::key(index);
        let value: StorageValue = borsh::to_vec(&sequencer_commitment_info)
            .expect("Batch proof info serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

pub struct BatchProofMethodIdAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BatchProofMethodIdAccessor<S> {
    const PREFIX: u8 = b'm';

    fn key() -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 1]; // 1 prefix + 1 byte

        key[0] = Self::PREFIX;

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    pub fn get(working_set: &mut WorkingSet<S>) -> Option<BatchProofMethodIds> {
        let key = Self::key();

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes)
                .expect("Batch proof method ids deserialization should not fail")
        })
    }

    pub fn insert(activation_l2_height: u64, method_id: [u32; 8], working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let mut method_ids = Self::get(working_set).unwrap_or_default();
        method_ids.push((activation_l2_height, method_id));
        let value: StorageValue = borsh::to_vec(&method_ids)
            .expect("Batch proof method ids serialization should not fail")
            .into();
        working_set.set(&key, value);
    }

    pub fn initialize(
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        working_set: &mut WorkingSet<S>,
    ) {
        let key = Self::key();
        let method_ids = Self::get(working_set).unwrap_or_default();

        assert!(
            method_ids.is_empty(),
            "When initialized, method ids must be empty!"
        );

        let value: StorageValue = borsh::to_vec(&initial_batch_proof_method_ids)
            .expect("Batch proof method ids serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

#[cfg(test)]
mod tests {
    use sov_modules_api::WorkingSet;
    use sov_modules_core::Storage;
    use sov_prover_storage_manager::{new_orphan_storage, ProverStorage};
    use sov_rollup_interface::da::SequencerCommitment;
    use sov_rollup_interface::witness::Witness;
    use sov_rollup_interface::zk::light_client_proof::output::VerifiedStateTransitionForSequencerCommitmentIndex;

    use super::{BlockHashAccessor, ChunkAccessor};
    use crate::circuit::accessors::{
        BatchProofMethodIdAccessor, SequencerCommitmentAccessor,
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
    };

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

    #[test]
    fn test_sequencer_commitment_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        let commitment = SequencerCommitment {
            merkle_root: [1; 32],
            index: 1,
            l2_end_block_number: 25,
        };
        SequencerCommitmentAccessor::<ProverStorage>::insert(
            1,
            commitment.clone(),
            &mut working_set,
        );

        assert_eq!(
            SequencerCommitmentAccessor::<ProverStorage>::get(1, &mut working_set).unwrap(),
            commitment
        );

        assert!(SequencerCommitmentAccessor::<ProverStorage>::get(2, &mut working_set).is_none());

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            SequencerCommitmentAccessor::<ProverStorage>::get(1, &mut working_set).unwrap(),
            commitment
        );

        assert!(SequencerCommitmentAccessor::<ProverStorage>::get(2, &mut working_set).is_none());
    }

    #[test]
    fn test_verified_state_transition_for_sequencer_commitment_index_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        let info = VerifiedStateTransitionForSequencerCommitmentIndex {
            initial_state_root: [1; 32],
            final_state_root: [2; 32],
            last_l2_height: 25,
        };
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::insert(
            1,
            info.clone(),
            &mut working_set,
        );

        assert_eq!(
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
                1,
                &mut working_set
            )
            .unwrap(),
            info
        );

        assert!(
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
                2,
                &mut working_set
            )
            .is_none()
        );

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
                1,
                &mut working_set
            )
            .unwrap(),
            info
        );

        assert!(
            VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
                2,
                &mut working_set
            )
            .is_none()
        );
    }

    #[test]
    fn test_batch_proof_method_id_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        assert!(BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).is_none());

        let initial_batch_proof_method_ids = vec![(3, [3; 8]), (4, [4; 8])];

        BatchProofMethodIdAccessor::<ProverStorage>::initialize(
            initial_batch_proof_method_ids.clone(),
            &mut working_set,
        );

        assert_eq!(
            BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            initial_batch_proof_method_ids
        );

        BatchProofMethodIdAccessor::<ProverStorage>::insert(1, [1; 8], &mut working_set);

        assert_eq!(
            BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            vec![(3, [3; 8]), (4, [4; 8]), (1, [1; 8])]
        );

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            vec![(3, [3; 8]), (4, [4; 8]), (1, [1; 8])]
        );
    }
}
