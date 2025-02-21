use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use jmt::storage::{NodeBatch, StaleNodeIndex, TreeWriter};
use jmt::{JellyfishMerkleTree, KeyHash, Version};
use sov_db::native_db::NativeDB;
use sov_db::state_db::StateDB;
use sov_modules_core::{
    CacheKey, NativeStorage, OrderedWrites, ReadWriteLog, Storage, StorageKey, StorageProof,
    StorageValue, Witness,
};
use sov_rollup_interface::stf::{StateDiff, StateRootTransition};
use sov_rollup_interface::zk::StorageRootHash;
use sov_schema_db::SchemaBatch;

use crate::config::Config;
use crate::{DefaultHasher, DefaultWitness};

/// A [`Storage`] implementation to be used by the prover in a native execution
/// environment (outside of the zkVM).
#[derive(Clone)]
pub struct ProverStorage {
    db: StateDB,
    native_db: NativeDB,
    init_version: u64,
    version: Arc<AtomicU64>,
    committable: bool,
}

impl ProverStorage {
    /// Creates a new [`ProverStorage`] instance from specified db handles.
    /// Gets latest version from [`StateDB`].
    pub fn committable_latest_version(db: StateDB, native_db: NativeDB) -> Self {
        let version = db.next_version() - 1;
        Self {
            db,
            native_db,
            init_version: version,
            version: Arc::new(AtomicU64::new(version)),
            committable: true,
        }
    }

    /// Creates a new [`ProverStorage`] instace from specified db handles and version.
    /// Storage is marked as uncommittable when created using this method.
    pub fn uncommittable_with_version(db: StateDB, native_db: NativeDB, version: Version) -> Self {
        Self {
            db,
            native_db,
            init_version: version,
            version: Arc::new(AtomicU64::new(version)),
            committable: false,
        }
    }

    /// Converts it to pair of readonly [`SchemaBatch`]s
    /// First is from [`StateDB`]
    /// Second is from [`NativeDB`]
    pub fn freeze(self) -> anyhow::Result<(SchemaBatch, SchemaBatch)> {
        let ProverStorage { db, native_db, .. } = self;
        let state_db_snapshot = db.freeze()?;
        let native_db_snapshot = native_db.freeze()?;
        Ok((state_db_snapshot, native_db_snapshot))
    }

    /// Whether the current storage is committable. Will be used
    /// for manager to determine commit to db.
    pub fn committable(&self) -> bool {
        self.committable
    }

    fn read_value(&self, key: &StorageKey) -> Option<StorageValue> {
        match self
            .db
            .get_value_option_by_key(self.version(), key.as_ref())
        {
            Ok(value) => value.map(Into::into),
            // It is ok to panic here, we assume the db is available and consistent.
            Err(e) => panic!("Unable to read value from db: {e}"),
        }
    }
}

pub struct ProverStateUpdate {
    pub(crate) node_batch: NodeBatch,
    pub key_preimages: Vec<(KeyHash, CacheKey)>,
    pub stale_state: BTreeSet<StaleNodeIndex>,
}

impl Storage for ProverStorage {
    type Witness = DefaultWitness;
    type RuntimeConfig = Config;
    type StateUpdate = ProverStateUpdate;

    fn get(&self, key: &StorageKey, witness: &mut Self::Witness) -> Option<StorageValue> {
        let val = self.read_value(key);
        witness.add_hint(&val);
        val
    }

    fn get_offchain(&self, key: &StorageKey, witness: &mut Self::Witness) -> Option<StorageValue> {
        let val = self
            .native_db
            .get_value_option(key.as_ref(), self.version())
            .unwrap()
            .map(Into::into);
        witness.add_hint(&val);
        val
    }

    #[cfg(feature = "native")]
    fn get_accessory(&self, key: &StorageKey) -> Option<StorageValue> {
        self.native_db
            .get_value_option(key.as_ref(), self.version())
            .unwrap()
            .map(Into::into)
    }

    fn compute_state_update(
        &self,
        state_log: &ReadWriteLog,
        witness: &mut Self::Witness,
    ) -> Result<(StateRootTransition, Self::StateUpdate, StateDiff), anyhow::Error> {
        let version = self.version();
        let jmt = JellyfishMerkleTree::<_, DefaultHasher>::new(&self.db);

        // Handle empty jmt
        if jmt.get_root_hash_option(version)?.is_none() {
            assert_eq!(version, 0);
            let (_, tree_update) = jmt
                .put_value_set([], version)
                .expect("JMT update must succeed");

            self.db
                .write_node_batch(&tree_update.node_batch)
                .expect("db write must succeed");
        }
        let prev_root = jmt
            .get_root_hash(version)
            .expect("Previous root hash was just populated");
        witness.add_hint(&prev_root.0);

        // For each value that's been read from the tree, read it from the logged JMT to populate hints
        for (key, read_value) in state_log.ordered_reads() {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let (result, proof) = jmt.get_with_proof(key_hash, version)?;
            if result.as_deref() != read_value.as_ref().map(|f| f.value.as_ref()) {
                anyhow::bail!("Bug! Incorrect value read from jmt");
            }
            witness.add_hint(&proof);
        }

        let pre_state = crate::stateful_statediff::build_pre_state(state_log.ordered_reads());
        let post_state =
            crate::stateful_statediff::build_post_state(state_log.iter_ordered_writes());

        let _st_statediff = crate::stateful_statediff::compress_state(pre_state, post_state);

        let mut key_preimages = vec![];
        let mut diff = vec![];

        // Compute the jmt update from the write batch
        let batch = state_log.iter_ordered_writes().map(|(key, value)| {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());

            let key_bytes = key.key.clone();
            let value_bytes = value.as_ref().map(|v| v.value.clone());

            diff.push((key_bytes, value_bytes.clone()));
            key_preimages.push((key_hash, key.clone()));

            (key_hash, value_bytes.map(|v| (*v).to_vec()))
        });

        let next_version = version + 1;

        let (new_root, update_proof, tree_update) = jmt
            .put_value_set_with_proof(batch, next_version)
            .expect("JMT update must succeed");

        let unparsed_len: usize = _st_statediff
            .unparsed
            .iter()
            .map(|(_k, v)| if let Some(x) = v { x.len() } else { 0 })
            .sum();
        let ststdiff = borsh::to_vec(&_st_statediff).unwrap();
        let _orig: crate::stateful_statediff::StatefulStateDiff =
            borsh::from_slice(&ststdiff).unwrap(); // check if we can parse it
        let prevdiff = borsh::to_vec(&diff).unwrap();

        println!(
            "ststdiff: {} bytes, diff: {} bytes, ststdiff unparsed: {} bytes \n",
            ststdiff.len(),
            prevdiff.len(),
            unparsed_len
        );

        witness.add_hint(&update_proof);
        witness.add_hint(&new_root.0);

        let state_update = ProverStateUpdate {
            node_batch: tree_update.node_batch,
            key_preimages,
            stale_state: tree_update.stale_node_index_batch,
        };

        // We need the state diff to be calculated only inside zk context.
        // The diff then can be used by special nodes to construct the state of the rollup by verifying the zk proof.
        // And constructing the tree from the diff.
        Ok((
            StateRootTransition {
                init_root: prev_root.into(),
                final_root: new_root.into(),
            },
            state_update,
            diff,
        ))
    }

    fn commit(
        &self,
        state_update: &Self::StateUpdate,
        accessory_writes: &OrderedWrites,
        offchain_log: &ReadWriteLog,
    ) {
        let next_version = self.version() + 1;

        // Integrity check
        for (version, _) in state_update.node_batch.values().keys() {
            assert_eq!(
                *version, next_version,
                "State update must be for next version"
            );
        }

        self.db
            .put_preimages(
                state_update
                    .key_preimages
                    .iter()
                    .map(|(key_hash, key)| (*key_hash, key.key.as_ref())),
            )
            .expect("Preimage put must succeed");

        self.native_db
            .set_values(
                accessory_writes
                    .iter()
                    .map(|(k, v_opt)| (k.key.to_vec(), v_opt.as_ref().map(|v| v.value.to_vec()))),
                next_version,
            )
            .expect("native db write must succeed");

        self.native_db
            .set_values(
                offchain_log
                    .iter_ordered_writes()
                    .map(|(k, v_opt)| (k.key.to_vec(), v_opt.as_ref().map(|v| v.value.to_vec()))),
                next_version,
            )
            .expect("native db write must succeed");

        // Write the state values last, since we base our view of what has been touched
        // on state. If the node crashes between the `native_db` update and this update,
        // then the whole `commit` will be re-run later so no data can be lost.
        self.db
            .write_node_batch(&state_update.node_batch)
            .expect("db write must succeed");

        // Write the stale state nodes which will be used by the pruner at a later stage for cleanup.
        self.db
            .set_stale_nodes(&state_update.stale_state)
            .expect("db set stale nodes must succeed");

        self.version.fetch_add(1, Ordering::SeqCst);
    }

    fn open_proof(
        state_root: StorageRootHash,
        state_proof: StorageProof,
    ) -> Result<(StorageKey, Option<StorageValue>), anyhow::Error> {
        let StorageProof { key, value, proof } = state_proof;
        let key_hash = KeyHash::with::<DefaultHasher>(key.as_ref());

        proof.verify(
            jmt::RootHash(state_root),
            key_hash,
            value.as_ref().map(|v| v.value()),
        )?;
        Ok((key, value))
    }

    // Based on assumption `validate_and_commit` increments version.
    fn is_empty(&self) -> bool {
        self.version() == 0
    }

    fn clone_with_version(&self, version: Version) -> Self {
        Self {
            db: self.db.clone(),
            native_db: self.native_db.clone(),
            init_version: self.init_version,
            version: Arc::new(AtomicU64::new(version)),
            // version change on the current storage should never be committed
            // as it will introduce weird cache problems
            committable: false,
        }
    }

    /// Get the last pruned L2 height from the native db.
    fn get_last_pruned_l2_height(&self) -> Result<Option<u64>, anyhow::Error> {
        self.native_db.get_last_pruned_l2_height()
    }
}

impl NativeStorage for ProverStorage {
    fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn init_version(&self) -> u64 {
        self.init_version
    }

    fn get_with_proof(&self, key: StorageKey, version: Version) -> StorageProof {
        let merkle = JellyfishMerkleTree::<StateDB, DefaultHasher>::new(&self.db);
        let (val_opt, proof) = merkle
            .get_with_proof(KeyHash::with::<DefaultHasher>(key.as_ref()), version)
            .unwrap();
        StorageProof {
            key,
            value: val_opt.map(StorageValue::from),
            proof,
        }
    }

    fn get_root_hash(&self, version: Version) -> anyhow::Result<StorageRootHash> {
        let temp_merkle: JellyfishMerkleTree<'_, StateDB, DefaultHasher> =
            JellyfishMerkleTree::new(&self.db);
        temp_merkle.get_root_hash(version).map(Into::into)
    }
}
