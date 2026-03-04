/// In this module we define the accessors for the different type of data we'll be using in the circuit.
/// We don't use the StateMap or Module system here, as our keys are all hashes of different things, we
/// don't want the serialization overhead.
use alloy_primitives::Address;
use sov_modules_api::{StateReaderAndWriter, WorkingSet};
use sov_modules_core::{Prefix, Storage, StorageKey, StorageValue};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::zk::light_client_proof::output::VerifiedStateTransitionForSequencerCommitmentIndex;
use sov_rollup_interface::RefCount;

use super::InitialBatchProofMethodIds;

/// Vector of activation height to method id
pub type BatchProofMethodIds = Vec<(u64, [u32; 8])>;

/// Accessor for managing block hash storage in the light client proof circuit
///
/// It handles storage and retrieval of L1 block hashes that have been processed by the light client prover.
/// Used to prove the existence of a previous hash.
/// It is a wrapper around working set where key is prefix + block hash and the value is an empty vector
pub struct BlockHashAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BlockHashAccessor<S> {
    /// Block hash storage prefix
    const PREFIX: u8 = b'b';

    /// Checks if a block hash exists in storage
    ///
    /// # Arguments
    /// * `hash` - The L1 block hash to check for
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Returns
    /// `true` if the hash exists in storage, `false` otherwise
    pub fn exists(hash: [u8; 32], working_set: &mut WorkingSet<S>) -> bool {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&hash);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        working_set.get(&key).is_some()
    }

    /// Inserts a block hash into storage
    ///
    /// # Arguments
    /// * `hash` - The L1 block hash to insert
    /// * `working_set` - Mutable reference to the working set for storage access
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

/// Accessor for managing block chunks storage in the light client proof circuit
///
/// This accessor handles storage and retrieval of proof chunks that are part of
/// aggregated proofs. Chunks are identified by their wtxid.
/// It is a wrapper around working set where key is prefix + wtxid and the value is the chunk's body
pub struct ChunkAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> ChunkAccessor<S> {
    /// Chunk storage prefix
    const PREFIX: u8 = b'c';

    /// Retrieves the body of a chunk if it exists in storage
    ///
    /// # Arguments
    /// * `wtxid` - The wtxid in which the proof was found
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Returns
    /// The chunk body if found, `None` otherwise
    pub fn get(wtxid: [u8; 32], working_set: &mut WorkingSet<S>) -> Option<RefCount<[u8]>> {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 33]; // 1 prefix + 32 hash

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&wtxid);

        let p = Prefix::from_slice(&key);

        let key = StorageKey::singleton_owned(p);

        working_set.get(&key).map(|v| v.into())
    }

    /// Inserts a new chunk into the light client prover state
    ///
    /// # Arguments
    /// * `wtxid` - The wtxid that corresponds to the chunk body
    /// * `body` - The chunk data to store
    /// * `working_set` - Mutable reference to the working set for storage access
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

/// Accessor for managing sequencer commitments storage in the light client proof circuit
///
/// This accessor handles storage and retrieval of sequencer commitments indexed by
/// their commitment index.
/// It is a wrapper around working set where key is prefix + sequencer commitment index
/// and the value is `SequencerCommitment` itself
pub struct SequencerCommitmentAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> SequencerCommitmentAccessor<S> {
    /// Sequencer commitment storage prefix
    const PREFIX: u8 = b's';

    /// Creates a storage key for a sequencer commitment index
    ///
    /// # Arguments
    /// * `index` - The commitment index to create a key for
    ///
    /// # Returns
    /// A storage key for the given commitment index
    fn key(index: u32) -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 5]; // 1 prefix + 4 bytes

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&index.to_be_bytes());

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves a sequencer commitment by its index if it exists
    ///
    /// # Arguments
    /// * `index` - The commitment index to retrieve
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Returns
    /// The sequencer commitment if found, `None` otherwise
    pub fn get(index: u32, working_set: &mut WorkingSet<S>) -> Option<SequencerCommitment> {
        let key = Self::key(index);

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes).expect("Commitment deserialization should not fail")
        })
    }

    /// Inserts a new sequencer commitment into the light client prover state
    ///
    /// # Arguments
    /// * `index` - The commitment index to store at
    /// * `commitment` - The sequencer commitment to store
    /// * `working_set` - Mutable reference to the working set for storage access
    pub fn insert(index: u32, commitment: SequencerCommitment, working_set: &mut WorkingSet<S>) {
        let key = Self::key(index);
        let value: StorageValue = borsh::to_vec(&commitment)
            .expect("Commitment serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

/// Accessor for managing verified state transitions indexed by sequencer commitment
///
/// This accessor handles storage and retrieval of sequencer commitments indexed by
/// their commitment index.
/// It is a wrapper around working set where key is prefix + sequencer commitment index
/// and the value is a `VerifiedStateTransitionForSequencerCommitmentIndex`
pub struct VerifiedStateTransitionForSequencerCommitmentIndexAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> VerifiedStateTransitionForSequencerCommitmentIndexAccessor<S> {
    /// Verified state transaction storage prefix
    const PREFIX: u8 = b'u';

    /// Creates a storage key for a verified state transition index
    ///
    /// # Arguments
    /// * `index` - The commitment index to create a key for
    ///
    /// # Returns
    /// A storage key for the given commitment index
    fn key(index: u32) -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 5]; // 1 prefix + 4 bytes

        key[0] = Self::PREFIX;
        key[1..].copy_from_slice(&index.to_be_bytes());

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves verified state transition info by commitment index if it exists
    ///
    /// # Arguments
    /// * `index` - The commitment index to retrieve
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Returns
    /// The verified state transition info if found, `None` otherwise
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

    /// Inserts new verified state transition info into the LCP state
    ///
    /// # Arguments
    /// * `index` - The commitment index to store at
    /// * `sequencer_commitment_info` - The verified state transition info to store
    /// * `working_set` - Mutable reference to the working set for storage access
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

/// Accessor for managing batch proof method ids
///
/// This accessor handles storage and retrieval of batch proof method ids that are
/// activated at different L2 block heights, allowing for upgrades to the proving system.
/// It is a wrapper around working set where key is the prefix
/// and the value is a borsh serialized vector of activation height to method id
pub struct BatchProofMethodIdAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BatchProofMethodIdAccessor<S> {
    /// Batch proof method ids storage prefix
    const PREFIX: u8 = b'm';

    /// Creates a storage key containing just the prefix
    /// # Returns
    /// A storage key for accessing batch proof method ids
    fn key() -> StorageKey {
        // use `StorageKey::singleton_owned` as a hack to create no serialization key
        let mut key = [0u8; 1]; // 1 prefix

        key[0] = Self::PREFIX;

        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves the batch proof method ids if they exist
    ///
    /// # Arguments
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Returns
    /// The batch proof method IDs if they exist, `None` otherwise
    pub fn get(working_set: &mut WorkingSet<S>) -> Option<BatchProofMethodIds> {
        let key = Self::key();

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes)
                .expect("Batch proof method ids deserialization should not fail")
        })
    }

    /// Inserts a new batch proof method id into the LCP state
    ///
    /// # Arguments
    /// * `activation_l2_height` - The L2 block height at which the method id is activated
    /// * `method_id` - The method id to store
    /// * `working_set` - Mutable reference to the working set for storage access
    pub fn insert(activation_l2_height: u64, method_id: [u32; 8], working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let mut method_ids = Self::get(working_set).unwrap_or_default();
        method_ids.push((activation_l2_height, method_id));
        let value: StorageValue = borsh::to_vec(&method_ids)
            .expect("Batch proof method ids serialization should not fail")
            .into();
        working_set.set(&key, value);
    }

    /// Initializes the batch proof method ids with an initial set of method ids. Must be called at most once and before any insertions.
    /// # Arguments
    /// * `initial_batch_proof_method_ids` - The initial set of method ids to store
    /// * `working_set` - Mutable reference to the working set for storage access
    ///
    /// # Panics
    /// Panics if the batch proof method ids are not empty when initializing
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

/// Accessor for managing security council (upgrade authority) addresses in the LCP state
///
/// This accessor handles storage and retrieval of security council addresses.
/// Initialized from compile-time constants on first LCP run, updatable via DA messages in the future.
/// The number of addresses is dynamic (not fixed at compile time).
pub struct SecurityCouncilAddressAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> SecurityCouncilAddressAccessor<S> {
    /// Security council address storage prefix
    const PREFIX: u8 = b'a';

    /// Creates a storage key containing just the prefix
    fn key() -> StorageKey {
        let mut key = [0u8; 1];
        key[0] = Self::PREFIX;
        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves the security council addresses if they exist
    ///
    /// # Returns
    /// The security council addresses as a Vec, or `None` if not initialized
    pub fn get(working_set: &mut WorkingSet<S>) -> Option<Vec<Address>> {
        let key = Self::key();

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            let raw: Vec<[u8; 20]> = borsh::from_slice(&bytes)
                .expect("Security council addresses deserialization should not fail");
            raw.iter().map(|a| Address::from_slice(a)).collect()
        })
    }

    /// Initializes the security council addresses. Must be called at most once.
    ///
    /// # Panics
    /// Panics if the addresses are already initialized
    pub fn initialize(addresses: &[Address], working_set: &mut WorkingSet<S>) {
        assert!(
            Self::get(working_set).is_none(),
            "Security council addresses must not already be initialized!"
        );
        Self::set(addresses, working_set);
    }

    /// Overwrites the current security council addresses (for future updates)
    pub fn set(addresses: &[Address], working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let raw: Vec<[u8; 20]> = addresses.iter().map(|a| a.0 .0).collect();
        let value: StorageValue = borsh::to_vec(&raw)
            .expect("Security council addresses serialization should not fail")
            .into();
        working_set.set(&key, value);
    }

    /// Removes a single address by value from the stored list
    pub fn remove(address: Address, working_set: &mut WorkingSet<S>) {
        let current = Self::get(working_set).expect("Security council addresses must exist");
        let filtered: Vec<[u8; 20]> = current
            .iter()
            .filter(|a| **a != address)
            .map(|a| a.0 .0)
            .collect();
        let key = Self::key();
        let value: StorageValue = borsh::to_vec(&filtered)
            .expect("Security council addresses serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

/// Accessor for managing the security council signature threshold in the LCP state
///
/// This accessor handles storage and retrieval of the minimum number of valid signatures
/// required to approve a method ID upgrade. Initialized on first LCP run, updatable via DA messages in the future.
pub struct SecurityCouncilThresholdAccessor<S: Storage> {
    /// Phantom data to make the accessor generic over the storage type
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> SecurityCouncilThresholdAccessor<S> {
    /// Security council threshold storage prefix
    const PREFIX: u8 = b't';

    /// Creates a storage key containing just the prefix
    fn key() -> StorageKey {
        let mut key = [0u8; 1];
        key[0] = Self::PREFIX;
        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves the security council signature threshold if it exists
    pub fn get(working_set: &mut WorkingSet<S>) -> Option<usize> {
        let key = Self::key();

        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            let val: u64 = borsh::from_slice(&bytes)
                .expect("Security council threshold deserialization should not fail");
            val as usize
        })
    }

    /// Initializes the security council threshold. Must be called at most once.
    ///
    /// # Panics
    /// Panics if the threshold is already initialized
    pub fn initialize(threshold: usize, working_set: &mut WorkingSet<S>) {
        assert!(
            Self::get(working_set).is_none(),
            "Security council threshold must not already be initialized!"
        );
        Self::set(threshold, working_set);
    }

    /// Overwrites the current security council threshold (for future updates)
    pub fn set(threshold: usize, working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let value: StorageValue = borsh::to_vec(&(threshold as u64))
            .expect("Security council threshold serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

/// Accessor for managing the sequencer DA public key in the LCP state
///
/// Initialized from compile-time constants on first LCP run, updatable via security council messages.
pub struct SequencerDaPubKeyAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> SequencerDaPubKeyAccessor<S> {
    const PREFIX: u8 = b'q';

    fn key() -> StorageKey {
        let mut key = [0u8; 1];
        key[0] = Self::PREFIX;
        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves the sequencer DA public key if it exists
    pub fn get(working_set: &mut WorkingSet<S>) -> Option<Vec<u8>> {
        let key = Self::key();
        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes)
                .expect("Sequencer DA pub key deserialization should not fail")
        })
    }

    /// Initializes the sequencer DA public key. Must be called at most once.
    pub fn initialize(pub_key: &[u8], working_set: &mut WorkingSet<S>) {
        assert!(
            Self::get(working_set).is_none(),
            "Sequencer DA pub key must not already be initialized!"
        );
        Self::set(pub_key, working_set);
    }

    /// Overwrites the current sequencer DA public key
    pub fn set(pub_key: &[u8], working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let value: StorageValue = borsh::to_vec(&pub_key.to_vec())
            .expect("Sequencer DA pub key serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

/// Accessor for managing the batch prover DA public key in the LCP state
///
/// Initialized from compile-time constants on first LCP run, updatable via security council messages.
pub struct BatchProverDaPubKeyAccessor<S: Storage> {
    phantom: core::marker::PhantomData<S>,
}

impl<S: Storage> BatchProverDaPubKeyAccessor<S> {
    const PREFIX: u8 = b'p';

    fn key() -> StorageKey {
        let mut key = [0u8; 1];
        key[0] = Self::PREFIX;
        let p = Prefix::from_slice(&key);
        StorageKey::singleton_owned(p)
    }

    /// Retrieves the batch prover DA public key if it exists
    pub fn get(working_set: &mut WorkingSet<S>) -> Option<Vec<u8>> {
        let key = Self::key();
        working_set.get(&key).map(|v| {
            let bytes: RefCount<[u8]> = v.into();
            borsh::from_slice(&bytes)
                .expect("Batch prover DA pub key deserialization should not fail")
        })
    }

    /// Initializes the batch prover DA public key. Must be called at most once.
    pub fn initialize(pub_key: &[u8], working_set: &mut WorkingSet<S>) {
        assert!(
            Self::get(working_set).is_none(),
            "Batch prover DA pub key must not already be initialized!"
        );
        Self::set(pub_key, working_set);
    }

    /// Overwrites the current batch prover DA public key
    pub fn set(pub_key: &[u8], working_set: &mut WorkingSet<S>) {
        let key = Self::key();
        let value: StorageValue = borsh::to_vec(&pub_key.to_vec())
            .expect("Batch prover DA pub key serialization should not fail")
            .into();
        working_set.set(&key, value);
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use sov_modules_api::WorkingSet;
    use sov_modules_core::Storage;
    use sov_prover_storage_manager::{new_orphan_storage, ProverStorage};
    use sov_rollup_interface::da::SequencerCommitment;
    use sov_rollup_interface::witness::Witness;
    use sov_rollup_interface::zk::light_client_proof::output::VerifiedStateTransitionForSequencerCommitmentIndex;

    use super::{BlockHashAccessor, ChunkAccessor};
    use crate::circuit::accessors::{
        BatchProofMethodIdAccessor, SecurityCouncilAddressAccessor,
        SecurityCouncilThresholdAccessor, SequencerCommitmentAccessor,
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

    #[test]
    fn test_security_council_address_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        assert!(SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).is_none());

        let addresses = vec![
            Address::new([1u8; 20]),
            Address::new([2u8; 20]),
            Address::new([3u8; 20]),
            Address::new([4u8; 20]),
            Address::new([5u8; 20]),
        ];

        SecurityCouncilAddressAccessor::<ProverStorage>::initialize(&addresses, &mut working_set);

        assert_eq!(
            SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            addresses
        );

        // Test set (overwrite) with a different number of addresses
        let new_addresses = vec![
            Address::new([10u8; 20]),
            Address::new([20u8; 20]),
            Address::new([30u8; 20]),
        ];
        SecurityCouncilAddressAccessor::<ProverStorage>::set(&new_addresses, &mut working_set);
        assert_eq!(
            SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            new_addresses
        );

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            new_addresses
        );
    }

    #[test]
    fn test_security_council_threshold_accessor() {
        let tmpdir = tempfile::tempdir().unwrap();
        let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
        let witness = Witness::default();
        let mut working_set =
            WorkingSet::with_witness(prover_storage.clone(), witness, Default::default());

        assert!(SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).is_none());

        SecurityCouncilThresholdAccessor::<ProverStorage>::initialize(3, &mut working_set);

        assert_eq!(
            SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            3
        );

        // Test set (overwrite)
        SecurityCouncilThresholdAccessor::<ProverStorage>::set(4, &mut working_set);
        assert_eq!(
            SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            4
        );

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (_, state_update, _) = prover_storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("should not fail");

        prover_storage.commit(&state_update, &vec![], &Default::default());

        // reset working set to actually read from storage
        let mut working_set = WorkingSet::new(prover_storage.clone());

        assert_eq!(
            SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap(),
            4
        );
    }
}
