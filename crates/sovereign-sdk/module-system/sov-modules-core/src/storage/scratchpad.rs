//! Runtime state machine definitions.

use alloc::collections::BTreeMap;
use core::mem;

use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::StorageRootHash;

use self::archival_state::ArchivalOffchainWorkingSet;
use crate::archival_state::{ArchivalAccessoryWorkingSet, ArchivalJmtWorkingSet};
use crate::common::Prefix;
use crate::storage::cache::{CacheLog, OrderedWrites, ReadWriteLog};
use crate::storage::{
    CacheKey, CacheValue, EncodeKeyLike, NativeStorage, StateCodec, StateValueCodec, Storage,
    StorageKey, StorageProof, StorageValue,
};
use crate::{ValueExists, Version};

/// A storage reader and writer
pub trait StateReaderAndWriter {
    /// Get a value from the storage.
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue>;

    /// Get a value from the storage with cache info.
    /// true if the value is read from the cache, false otherwise.
    fn get_with_cache_info(&mut self, key: &StorageKey) -> (Option<StorageValue>, bool);

    /// Replaces a storage value.
    fn set(&mut self, key: &StorageKey, value: StorageValue);

    /// Deletes a storage value.
    fn delete(&mut self, key: &StorageKey);

    /// Replaces a storage value with the provided prefix, using the provided codec.
    fn set_value<Q, K, V, Codec>(
        &mut self,
        prefix: &Prefix,
        storage_key: &Q,
        value: &V,
        codec: &Codec,
    ) where
        Q: ?Sized,
        Codec: StateCodec,
        Codec::KeyCodec: EncodeKeyLike<Q, K>,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::new(prefix, storage_key, codec.key_codec());
        let storage_value = StorageValue::new(value, codec.value_codec());
        self.set(&storage_key, storage_value);
    }

    /// Replaces a storage value with a singleton prefix. For more information, check
    /// [StorageKey::singleton].
    fn set_singleton<V, Codec>(&mut self, prefix: &Prefix, value: &V, codec: &Codec)
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::singleton(prefix);
        let storage_value = StorageValue::new(value, codec.value_codec());
        self.set(&storage_key, storage_value);
    }

    /// Get a decoded value from the storage.
    fn get_decoded<V, Codec>(&mut self, storage_key: &StorageKey, codec: &Codec) -> Option<V>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_value = self.get(storage_key)?;

        Some(
            codec
                .value_codec()
                .decode_value_unwrap(storage_value.value()),
        )
    }

    /// Get a value from the storage.
    fn get_value<Q, K, V, Codec>(
        &mut self,
        prefix: &Prefix,
        storage_key: &Q,
        codec: &Codec,
    ) -> Option<V>
    where
        Q: ?Sized,
        Codec: StateCodec,
        Codec::KeyCodec: EncodeKeyLike<Q, K>,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::new(prefix, storage_key, codec.key_codec());
        self.get_decoded(&storage_key, codec)
    }

    /// Same thing as `get_value`, but also verifies the value with a given function only when the
    /// value is not found in the cache and read from the storage.
    fn get_value_with_cache_info<Q, K, V, Codec>(
        &mut self,
        prefix: &Prefix,
        storage_key: &Q,
        codec: &Codec,
    ) -> (Option<V>, bool)
    where
        Q: ?Sized,
        Codec: StateCodec,
        Codec::KeyCodec: EncodeKeyLike<Q, K>,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::new(prefix, storage_key, codec.key_codec());
        let (storage_value, read_from_cache) = self.get_with_cache_info(&storage_key);

        let value = storage_value.map(|storage_value| {
            codec
                .value_codec()
                .decode_value_unwrap(storage_value.value())
        });

        (value, read_from_cache)
    }

    /// Get a singleton value from the storage. For more information, check [StorageKey::singleton].
    fn get_singleton<V, Codec>(&mut self, prefix: &Prefix, codec: &Codec) -> Option<V>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::singleton(prefix);
        self.get_decoded(&storage_key, codec)
    }

    /// Removes a value from the storage.
    fn remove_value<Q, K, V, Codec>(
        &mut self,
        prefix: &Prefix,
        storage_key: &Q,
        codec: &Codec,
    ) -> Option<V>
    where
        Q: ?Sized,
        Codec: StateCodec,
        Codec::KeyCodec: EncodeKeyLike<Q, K>,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::new(prefix, storage_key, codec.key_codec());
        let storage_value = self.get_decoded(&storage_key, codec)?;
        self.delete(&storage_key);
        Some(storage_value)
    }

    /// Removes a singleton from the storage. For more information, check [StorageKey::singleton].
    fn remove_singleton<V, Codec>(&mut self, prefix: &Prefix, codec: &Codec) -> Option<V>
    where
        Codec: StateCodec,
        Codec::ValueCodec: StateValueCodec<V>,
    {
        let storage_key = StorageKey::singleton(prefix);
        let storage_value = self.get_decoded(&storage_key, codec)?;
        self.delete(&storage_key);
        Some(storage_value)
    }

    /// Deletes a value from the storage.
    fn delete_value<Q, K, Codec>(&mut self, prefix: &Prefix, storage_key: &Q, codec: &Codec)
    where
        Q: ?Sized,
        Codec: StateCodec,
        Codec::KeyCodec: EncodeKeyLike<Q, K>,
    {
        let storage_key = StorageKey::new(prefix, storage_key, codec.key_codec());
        self.delete(&storage_key);
    }

    /// Deletes a singleton from the storage. For more information, check [StorageKey::singleton].
    fn delete_singleton(&mut self, prefix: &Prefix) {
        let storage_key = StorageKey::singleton(prefix);
        self.delete(&storage_key);
    }
}

/// `StateDelta` is a wrapper around a `Storage` implementation that keeps track of the
/// cache log, reads and witness.
struct StateDelta<S: Storage> {
    storage: S,
    cache_log: CacheLog,
    uncommitted_writes: BTreeMap<CacheKey, Option<CacheValue>>,
    ordered_storage_reads: Vec<(CacheKey, Option<CacheValue>)>,
    witness: Witness,
    version: Option<Version>,
}

impl<S: Storage> StateDelta<S> {
    fn new(storage: S, version: Option<Version>) -> Self {
        Self::with_witness(storage, Default::default(), version)
    }

    fn with_witness(storage: S, witness: Witness, version: Option<Version>) -> Self {
        Self {
            storage,
            cache_log: CacheLog::default(),
            uncommitted_writes: BTreeMap::default(),
            ordered_storage_reads: Vec::default(),
            witness,
            version,
        }
    }

    fn with_witness_and_log(
        storage: S,
        witness: Witness,
        state_log: ReadWriteLog,
        version: Option<Version>,
    ) -> Self {
        Self {
            storage,
            cache_log: state_log.into_cache_log(),
            uncommitted_writes: BTreeMap::default(),
            ordered_storage_reads: Vec::default(),
            witness,
            version,
        }
    }

    /// Commits the uncommitted writes to the cache log.
    fn commit(mut self) -> Self {
        let writes = mem::take(&mut self.uncommitted_writes);
        for (key, value) in writes {
            self.cache_log.add_write(key, value);
        }
        self
    }

    /// Reverts the uncommitted writes.
    fn revert(mut self) -> Self {
        self.uncommitted_writes.clear();
        self
    }

    /// Takes ownership of the cache log, ordered reads and witness. Returned `ReadWriteLog`
    /// can be used to recreate the `StateDelta` again with a new version which will be useful
    /// for reusing the same cache log to generate less witness in the subsequent calls.
    fn freeze(&mut self) -> (ReadWriteLog, Witness) {
        let ordered_reads = mem::take(&mut self.ordered_storage_reads);
        let cache_log = mem::take(&mut self.cache_log);

        let read_write_log = ReadWriteLog {
            ordered_reads,
            cache_log,
        };
        let witness = mem::take(&mut self.witness);

        (read_write_log, witness)
    }
}

impl<S: Storage> StateReaderAndWriter for StateDelta<S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        let cache_key = key.to_cache_key_version(self.version);

        if let Some(value) = self.uncommitted_writes.get(&cache_key) {
            return value.as_ref().cloned().map(Into::into);
        }

        match self.cache_log.get_value(&cache_key) {
            ValueExists::Yes(value) => value.map(Into::into),
            ValueExists::No => {
                let storage_value = self.storage.get(key, &mut self.witness);
                let cache_value = storage_value.as_ref().map(|v| v.clone().into_cache_value());

                self.cache_log
                    .add_read(cache_key.clone(), cache_value.clone())
                    .expect("Read from CacheLog failed");
                self.ordered_storage_reads.push((cache_key, cache_value));

                storage_value
            }
        }
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        self.uncommitted_writes.insert(
            key.to_cache_key_version(self.version),
            Some(value.into_cache_value()),
        );
    }

    fn delete(&mut self, key: &StorageKey) {
        self.uncommitted_writes
            .insert(key.to_cache_key_version(self.version), None);
    }

    fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
        unimplemented!("Only Offchain state supports get_with_cache_info")
    }
}

/// `AccessoryDelta` is a wrapper around a `Storage` implementation that keeps track of the
/// committed and uncommitted writes. Accessory state does not need witness as it deals with the
/// data that doesn't require proving in the ZK environment.
struct AccessoryDelta<S: Storage> {
    storage: S,
    committed_writes: BTreeMap<CacheKey, Option<CacheValue>>,
    uncommitted_writes: BTreeMap<CacheKey, Option<CacheValue>>,
    version: Option<Version>,
}

impl<S: Storage> AccessoryDelta<S> {
    fn new(storage: S, version: Option<Version>) -> Self {
        Self {
            storage,
            committed_writes: BTreeMap::default(),
            uncommitted_writes: BTreeMap::default(),
            version,
        }
    }

    fn commit(mut self) -> Self {
        self.committed_writes.append(&mut self.uncommitted_writes);
        self
    }

    fn revert(mut self) -> Self {
        self.uncommitted_writes.clear();
        self
    }

    fn freeze(&mut self) -> OrderedWrites {
        mem::take(&mut self.committed_writes).into_iter().collect()
    }
}

impl<S: Storage> StateReaderAndWriter for AccessoryDelta<S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        let cache_key = key.to_cache_key_version(self.version);

        if let Some(value) = self.uncommitted_writes.get(&cache_key) {
            return value.as_ref().cloned().map(Into::into);
        }

        if let Some(value) = self.committed_writes.get(&cache_key) {
            return value.as_ref().cloned().map(Into::into);
        }

        self.storage.get_accessory(key)
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        self.uncommitted_writes.insert(
            key.to_cache_key_version(self.version),
            Some(value.into_cache_value()),
        );
    }

    fn delete(&mut self, key: &StorageKey) {
        self.uncommitted_writes
            .insert(key.to_cache_key_version(self.version), None);
    }

    fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
        unimplemented!("Only Offchain state supports get_with_cache_info")
    }
}

/// `OffchainDelta` is a wrapper around a `Storage` implementation that keeps track of the
/// access to the offchain storage.
struct OffchainDelta<S: Storage> {
    storage: S,
    cache_log: CacheLog,
    uncommitted_writes: BTreeMap<CacheKey, Option<CacheValue>>,
    witness: Witness,
    version: Option<Version>,
}

impl<S: Storage> OffchainDelta<S> {
    fn new(storage: S, version: Option<Version>) -> Self {
        Self::with_witness(storage, Default::default(), version)
    }

    fn with_witness(storage: S, witness: Witness, version: Option<Version>) -> Self {
        Self {
            storage,
            cache_log: CacheLog::default(),
            uncommitted_writes: BTreeMap::default(),
            witness,
            version,
        }
    }

    fn with_witness_and_log(
        storage: S,
        witness: Witness,
        offchain_log: ReadWriteLog,
        version: Option<Version>,
    ) -> Self {
        Self {
            storage,
            cache_log: offchain_log.into_cache_log(),
            uncommitted_writes: BTreeMap::default(),
            witness,
            version,
        }
    }

    /// Commits the uncommitted writes to the cache log.
    fn commit(mut self) -> Self {
        let writes = mem::take(&mut self.uncommitted_writes);
        for (key, value) in writes {
            self.cache_log.add_write(key, value);
        }
        self
    }

    /// Reverts the uncommitted writes.
    fn revert(mut self) -> Self {
        self.uncommitted_writes.clear();
        self
    }

    /// Takes ownership of the cache log, ordered reads and witness. Returned `ReadWriteLog`
    /// can be used to recreate the `OffchainDelta` again with a new version which will be useful
    /// for reusing the same cache log to generate less witness in the subsequent calls.
    fn freeze(&mut self) -> (ReadWriteLog, Witness) {
        let cache_log = mem::take(&mut self.cache_log);

        let read_write_log = ReadWriteLog {
            ordered_reads: Vec::default(),
            cache_log,
        };
        let witness = mem::take(&mut self.witness);

        (read_write_log, witness)
    }
}

impl<S: Storage> StateReaderAndWriter for OffchainDelta<S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        let cache_key = key.to_cache_key_version(self.version);

        if let Some(value) = self.uncommitted_writes.get(&cache_key) {
            return value.as_ref().cloned().map(Into::into);
        }

        match self.cache_log.get_value(&cache_key) {
            ValueExists::Yes(value) => value.map(Into::into),
            ValueExists::No => {
                let storage_value = self.storage.get_offchain(key, &mut self.witness);
                let cache_value = storage_value.as_ref().map(|v| v.clone().into_cache_value());

                self.cache_log
                    .add_read(cache_key, cache_value)
                    .expect("Read from CacheLog failed");

                storage_value
            }
        }
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        self.uncommitted_writes.insert(
            key.to_cache_key_version(self.version),
            Some(value.into_cache_value()),
        );
    }

    fn delete(&mut self, key: &StorageKey) {
        self.uncommitted_writes
            .insert(key.to_cache_key_version(self.version), None);
    }

    fn get_with_cache_info(&mut self, key: &StorageKey) -> (Option<StorageValue>, bool) {
        let cache_key = key.to_cache_key_version(self.version);

        if let Some(value) = self.uncommitted_writes.get(&cache_key) {
            return (value.as_ref().cloned().map(Into::into), true);
        }

        match self.cache_log.get_value(&cache_key) {
            ValueExists::Yes(value) => (value.map(Into::into), true),
            ValueExists::No => {
                let storage_value = self.storage.get_offchain(key, &mut self.witness);
                let cache_value = storage_value.as_ref().map(|v| v.clone().into_cache_value());

                self.cache_log
                    .add_read(cache_key, cache_value)
                    .expect("Read from CacheLog failed");

                (storage_value, false)
            }
        }
    }
}

/// This structure is responsible for storing the `read-write` set.
///
/// A [`StateCheckpoint`] can be obtained from a [`WorkingSet`] in two ways:
///  1. With [`WorkingSet::checkpoint`].
///  2. With [`WorkingSet::revert`].
pub struct StateCheckpoint<S: Storage> {
    delta: StateDelta<S>,
    accessory_delta: AccessoryDelta<S>,
    offchain_delta: OffchainDelta<S>,
}

impl<S: Storage> StateCheckpoint<S> {
    /// Creates a new [`StateCheckpoint`] instance without any changes, backed
    /// by the given [`Storage`].
    pub fn new(inner: S) -> Self {
        Self::with_witness(inner, Default::default(), Default::default())
    }

    /// Creates a new [`StateCheckpoint`] instance without any changes, backed
    /// by the given [`Storage`] and witness.
    pub fn with_witness(inner: S, state_witness: Witness, offchain_witness: Witness) -> Self {
        Self {
            delta: StateDelta::with_witness(inner.clone(), state_witness, None),
            accessory_delta: AccessoryDelta::new(inner.clone(), None),
            offchain_delta: OffchainDelta::with_witness(inner, offchain_witness, None),
        }
    }

    /// Creates a new [`StateCheckpoint`] instance without any changes, backed
    /// by the given [`Storage`], witness, and prepopulated state cache log.
    pub fn with_witness_and_log(
        inner: S,
        state_witness: Witness,
        offchain_witness: Witness,
        state_log: ReadWriteLog,
        offchain_log: ReadWriteLog,
    ) -> Self {
        Self {
            delta: StateDelta::with_witness_and_log(inner.clone(), state_witness, state_log, None),
            accessory_delta: AccessoryDelta::new(inner.clone(), None),
            offchain_delta: OffchainDelta::with_witness_and_log(
                inner,
                offchain_witness,
                offchain_log,
                None,
            ),
        }
    }

    /// Transforms this [`StateCheckpoint`] back into a [`WorkingSet`].
    pub fn to_revertable(self) -> WorkingSet<S> {
        WorkingSet {
            delta: self.delta,
            offchain_delta: self.offchain_delta,
            accessory_delta: self.accessory_delta,
            archival_working_set: None,
            archival_accessory_working_set: None,
            archival_offchain_working_set: None,
        }
    }

    /// Extracts ordered reads, writes, and witness from this [`StateCheckpoint`].
    ///
    /// You can then use these to call [`Storage::validate_and_commit`] or some
    /// of the other related [`Storage`] methods. Note that this data is moved
    /// **out** of the [`StateCheckpoint`] i.e. it can't be extracted twice.
    pub fn freeze(&mut self) -> (ReadWriteLog, Witness) {
        self.delta.freeze()
    }

    /// Extracts ordered reads and writes of accessory state from this
    /// [`StateCheckpoint`].
    ///
    /// You can then use these to call
    /// [`Storage::validate_and_commit_with_accessory_update`], together with
    /// the data extracted with [`StateCheckpoint::freeze`].
    pub fn freeze_non_provable(&mut self) -> OrderedWrites {
        self.accessory_delta.freeze()
    }

    /// Extracts ordered reads and writes of offchain state from this
    /// [`StateCheckpoint`].
    ///
    /// You can then use these to call
    /// [`Storage::validate_and_commit_with_accessory_update`], together with
    /// the data extracted with [`StateCheckpoint::freeze`].
    pub fn freeze_offchain(&mut self) -> (ReadWriteLog, Witness) {
        self.offchain_delta.freeze()
    }
}

/// This structure contains the read-write set and the events collected during the execution of a transaction.
/// There are two ways to convert it into a StateCheckpoint:
/// 1. By using the checkpoint() method, where all the changes are added to the underlying StateCheckpoint.
/// 2. By using the revert method, where the most recent changes are reverted and the previous `StateCheckpoint` is returned.
pub struct WorkingSet<S: Storage> {
    delta: StateDelta<S>,
    accessory_delta: AccessoryDelta<S>,
    offchain_delta: OffchainDelta<S>,
    archival_working_set: Option<ArchivalJmtWorkingSet<S>>,
    archival_offchain_working_set: Option<ArchivalOffchainWorkingSet<S>>,
    archival_accessory_working_set: Option<ArchivalAccessoryWorkingSet<S>>,
}

impl<S: Storage> WorkingSet<S> {
    /// Creates a new [`WorkingSet`] instance backed by the given [`Storage`].
    ///
    /// The witness value is set to [`Default::default`]. Use
    /// [`WorkingSet::with_witness`] to set a custom witness value.
    pub fn new(inner: S) -> Self {
        StateCheckpoint::new(inner).to_revertable()
    }

    /// Creates a new [`WorkingSet`] instance backed by the given [`Storage`]
    /// and a custom witness value.
    pub fn with_witness(inner: S, state_witness: Witness, offchain_witness: Witness) -> Self {
        StateCheckpoint::with_witness(inner, state_witness, offchain_witness).to_revertable()
    }

    /// Creates a new [`WorkingSet`] instance backed by the given [`Storage`],
    /// a custom witness value and a prepopulated state log to use as cache.
    pub fn with_witness_and_log(
        inner: S,
        state_witness: Witness,
        offchain_witness: Witness,
        state_log: ReadWriteLog,
        offchain_log: ReadWriteLog,
    ) -> Self {
        StateCheckpoint::with_witness_and_log(
            inner,
            state_witness,
            offchain_witness,
            state_log,
            offchain_log,
        )
        .to_revertable()
    }

    /// Returns a handler for the accessory state (non-JMT state).
    ///
    /// You can use this method when calling getters and setters on accessory
    /// state containers, like AccessoryStateMap.
    pub fn accessory_state(&mut self) -> AccessoryWorkingSet<S> {
        AccessoryWorkingSet { ws: self }
    }

    /// Returns a handler for the offchain state (non-JMT state).
    ///
    /// You can use this method when calling getters and setters on offchain
    /// state containers, like OffchainStateMap.
    pub fn offchain_state(&mut self) -> OffchainWorkingSet<S> {
        OffchainWorkingSet { ws: self }
    }

    /// Returns a handler for the archival state (JMT state).
    fn archival_state(&mut self, version: Version) -> ArchivalJmtWorkingSet<S> {
        let storage = self.delta.storage.clone_with_version(version);
        ArchivalJmtWorkingSet::new(storage, version)
    }

    /// Returns a handler for the archival offchain state.
    fn archival_offchain_state(&mut self, version: Version) -> ArchivalOffchainWorkingSet<S> {
        let storage = self.offchain_delta.storage.clone_with_version(version);
        ArchivalOffchainWorkingSet::new(storage, version)
    }

    /// Returns a handler for the archival accessory state (non-JMT state).
    fn archival_accessory_state(&mut self, version: Version) -> ArchivalAccessoryWorkingSet<S> {
        let storage = self.accessory_delta.storage.clone_with_version(version);
        ArchivalAccessoryWorkingSet::new(storage, version)
    }

    /// Sets archival version for a working set
    pub fn set_archival_version(&mut self, version: Version) {
        self.archival_working_set = Some(self.archival_state(version));
        self.archival_offchain_working_set = Some(self.archival_offchain_state(version));
        self.archival_accessory_working_set = Some(self.archival_accessory_state(version));
    }

    /// Unset archival version
    pub fn unset_archival_version(&mut self) {
        self.archival_working_set = None;
        self.archival_offchain_working_set = None;
        self.archival_accessory_working_set = None;
    }

    /// Turns this [`WorkingSet`] into a [`StateCheckpoint`], in preparation for
    /// committing the changes to the underlying [`Storage`] via
    /// [`StateCheckpoint::freeze`].
    pub fn checkpoint(self) -> StateCheckpoint<S> {
        StateCheckpoint {
            delta: self.delta.commit(),
            accessory_delta: self.accessory_delta.commit(),
            offchain_delta: self.offchain_delta.commit(),
        }
    }

    /// Reverts the most recent changes to this [`WorkingSet`], returning a pristine
    /// [`StateCheckpoint`] instance.
    pub fn revert(self) -> StateCheckpoint<S> {
        StateCheckpoint {
            delta: self.delta.revert(),
            accessory_delta: self.accessory_delta.revert(),
            offchain_delta: self.offchain_delta.revert(),
        }
    }

    /// Fetches given value and provides a proof of it presence/absence.
    pub fn get_with_proof(&mut self, key: StorageKey, version: Version) -> StorageProof
    where
        S: NativeStorage,
    {
        // First inner is `R.clone()evertableWriter` and second inner is actually a `Storage` instance
        self.delta.storage.get_with_proof(key, version)
    }

    /// Get the root hash of the tree.
    pub fn get_root_hash(&mut self, version: Version) -> Result<StorageRootHash, anyhow::Error>
    where
        S: NativeStorage,
    {
        // First inner is `RevertableWriter` and second inner is actually a `Storage` instance
        self.delta.storage.get_root_hash(version)
    }

    /// Get the last pruned L2 height.
    pub fn get_last_pruned_l2_height(&mut self) -> Result<Option<u64>, anyhow::Error> {
        self.delta.storage.get_last_pruned_l2_height()
    }
}

impl<S: Storage> StateReaderAndWriter for WorkingSet<S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        match &mut self.archival_working_set {
            None => self.delta.get(key),
            Some(ref mut archival_working_set) => archival_working_set.get(key),
        }
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        match &mut self.archival_working_set {
            None => self.delta.set(key, value),
            Some(ref mut archival_working_set) => archival_working_set.set(key, value),
        }
    }

    fn delete(&mut self, key: &StorageKey) {
        match &mut self.archival_working_set {
            None => self.delta.delete(key),
            Some(ref mut archival_working_set) => archival_working_set.delete(key),
        }
    }

    fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
        unimplemented!("Only Offchain state supports get_with_cache_info")
    }
}

/// A wrapper over [`WorkingSet`] that only allows access to the accessory
/// state (non-JMT state).
pub struct AccessoryWorkingSet<'a, S: Storage> {
    ws: &'a mut WorkingSet<S>,
}

impl<S: Storage> StateReaderAndWriter for AccessoryWorkingSet<'_, S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        if !cfg!(feature = "native") {
            None
        } else {
            match &mut self.ws.archival_accessory_working_set {
                None => self.ws.accessory_delta.get(key),
                Some(ref mut archival_working_set) => archival_working_set.get(key),
            }
        }
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        match &mut self.ws.archival_accessory_working_set {
            None => self.ws.accessory_delta.set(key, value),
            Some(ref mut archival_working_set) => archival_working_set.set(key, value),
        }
    }

    fn delete(&mut self, key: &StorageKey) {
        match &mut self.ws.archival_accessory_working_set {
            None => self.ws.accessory_delta.delete(key),
            Some(ref mut archival_working_set) => archival_working_set.delete(key),
        }
    }

    fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
        unimplemented!()
    }
}

/// A wrapper over [`WorkingSet`] that only allows access to the accessory
/// state (non-JMT state).
pub struct OffchainWorkingSet<'a, S: Storage> {
    ws: &'a mut WorkingSet<S>,
}

impl<S: Storage> StateReaderAndWriter for OffchainWorkingSet<'_, S> {
    fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
        match &mut self.ws.archival_offchain_working_set {
            None => self.ws.offchain_delta.get(key),
            Some(ref mut archival_working_set) => archival_working_set.get(key),
        }
    }

    fn set(&mut self, key: &StorageKey, value: StorageValue) {
        match &mut self.ws.archival_offchain_working_set {
            None => self.ws.offchain_delta.set(key, value),
            Some(ref mut archival_working_set) => archival_working_set.set(key, value),
        }
    }

    fn delete(&mut self, key: &StorageKey) {
        match &mut self.ws.archival_offchain_working_set {
            None => self.ws.offchain_delta.delete(key),
            Some(ref mut archival_working_set) => archival_working_set.delete(key),
        }
    }

    fn get_with_cache_info(&mut self, key: &StorageKey) -> (Option<StorageValue>, bool) {
        match &mut self.ws.archival_offchain_working_set {
            None => self.ws.offchain_delta.get_with_cache_info(key),
            Some(ref mut archival_working_set) => archival_working_set.get_with_cache_info(key),
        }
    }
}

/// Module for archival state
pub mod archival_state {
    use super::*;

    /// Archival JMT
    pub struct ArchivalJmtWorkingSet<S: Storage> {
        delta: StateDelta<S>,
    }

    impl<S: Storage> ArchivalJmtWorkingSet<S> {
        /// create a new instance of ArchivalJmtWorkingSet
        pub fn new(inner: S, version: Version) -> Self {
            Self {
                delta: StateDelta::new(inner, Some(version)),
            }
        }
    }

    /// Archival Accessory
    pub struct ArchivalAccessoryWorkingSet<S: Storage> {
        delta: AccessoryDelta<S>,
    }

    impl<S: Storage> ArchivalAccessoryWorkingSet<S> {
        /// create a new instance of ArchivalAccessoryWorkingSet
        pub fn new(inner: S, version: Version) -> Self {
            Self {
                delta: AccessoryDelta::new(inner, Some(version)),
            }
        }
    }

    impl<S: Storage> StateReaderAndWriter for ArchivalJmtWorkingSet<S> {
        fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
            self.delta.get(key)
        }

        fn set(&mut self, key: &StorageKey, value: StorageValue) {
            self.delta.set(key, value)
        }

        fn delete(&mut self, key: &StorageKey) {
            self.delta.delete(key)
        }

        fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
            unimplemented!("Only Offchain state supports get_with_cache_info")
        }
    }

    impl<S: Storage> StateReaderAndWriter for ArchivalAccessoryWorkingSet<S> {
        fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
            if !cfg!(feature = "native") {
                None
            } else {
                self.delta.get(key)
            }
        }

        fn set(&mut self, key: &StorageKey, value: StorageValue) {
            self.delta.set(key, value)
        }

        fn delete(&mut self, key: &StorageKey) {
            self.delta.delete(key)
        }

        fn get_with_cache_info(&mut self, _key: &StorageKey) -> (Option<StorageValue>, bool) {
            unimplemented!("Only Offchain state supports get_with_cache_info")
        }
    }

    /// Archival Offchain
    pub struct ArchivalOffchainWorkingSet<S: Storage> {
        delta: OffchainDelta<S>,
    }

    impl<S: Storage> ArchivalOffchainWorkingSet<S> {
        /// create a new instance of ArchivalOffchainWorkingSet
        pub fn new(inner: S, version: Version) -> Self {
            Self {
                delta: OffchainDelta::new(inner, Some(version)),
            }
        }
    }

    impl<S: Storage> StateReaderAndWriter for ArchivalOffchainWorkingSet<S> {
        fn get(&mut self, key: &StorageKey) -> Option<StorageValue> {
            if !cfg!(feature = "native") {
                None
            } else {
                self.delta.get(key)
            }
        }

        fn set(&mut self, key: &StorageKey, value: StorageValue) {
            self.delta.set(key, value)
        }

        fn delete(&mut self, key: &StorageKey) {
            self.delta.delete(key)
        }

        fn get_with_cache_info(&mut self, key: &StorageKey) -> (Option<StorageValue>, bool) {
            self.delta.get_with_cache_info(key)
        }
    }
}
