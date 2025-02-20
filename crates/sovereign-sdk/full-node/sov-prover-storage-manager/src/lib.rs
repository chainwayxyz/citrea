use std::sync::Arc;

use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use sov_schema_db::DB;
use sov_state::storage::NativeStorage;
pub use sov_state::ProverStorage;

#[derive(Clone)]
pub struct ProverStorageManager {
    state_db: Arc<DB>,
    native_db: Arc<DB>,
}

impl ProverStorageManager {
    fn with_db_handles(state_db: Arc<DB>, native_db: Arc<DB>) -> Self {
        Self {
            state_db,
            native_db,
        }
    }

    /// Create new [`ProverStorageManager`] from state config
    pub fn new(config: sov_state::config::Config) -> anyhow::Result<Self> {
        let rocksdb_config =
            RocksdbConfig::new(config.path.as_path(), config.db_max_open_files, None);
        let state_db = Arc::new(StateDB::setup_schema_db(&rocksdb_config)?);
        let native_db = Arc::new(NativeDB::setup_schema_db(&rocksdb_config)?);
        Ok(Self::with_db_handles(state_db, native_db))
    }

    /// Creates a new [`ProverStorage`] to run the provided `l2_height` updates. Created storage is uncommittable
    /// to underlying rocksdb when [`ProverStorageManager::finalize_storage`] method is called.
    pub fn create_storage_for_l2_height(&self, l2_height: u64) -> ProverStorage {
        let version = l2_height;

        let state_db = StateDB::new(self.state_db.clone());
        let native_db = NativeDB::new(self.native_db.clone());

        let storage = ProverStorage::uncommittable_with_version(state_db, native_db, version);
        tracing::debug!("Created uncommittable storage for l2 height {}", l2_height);

        storage
    }

    /// Creates a new [`ProverStorage`] to run the next `l2_height`.
    pub fn create_storage_for_next_l2_height(&self) -> ProverStorage {
        let state_db = StateDB::new(self.state_db.clone());
        let native_db = NativeDB::new(self.native_db.clone());

        let storage = ProverStorage::committable_latest_version(state_db, native_db);
        tracing::debug!("Created storage for next l2 height {}", storage.version());

        storage
    }

    /// Creates a new [`ProverStorage`] that always has the final view of the state,
    /// and can not be committed. If needed, use [`ProverStorage::clone_with_version`]
    /// to create a storage with different version without overriding existing one.
    pub fn create_final_view_storage(&self) -> ProverStorage {
        let state_db = StateDB::new(self.state_db.clone());
        let native_db = NativeDB::new(self.native_db.clone());

        let storage = ProverStorage::uncommittable_with_version(state_db, native_db, u64::MAX);
        tracing::debug!("Created always latest view storage");

        storage
    }

    /// Commits all the changes to `ProverStorage` to underlying database.
    /// If storage is a snapshot, nothing is committed, an false is returned.
    pub fn finalize_storage(&self, storage: ProverStorage) {
        assert!(
            storage.committable(),
            "Uncommittable storage should never be finalized"
        );

        tracing::debug!("Finalizing storage on l2 height {}", storage.init_version());

        let (state_batch, native_batch) = storage.freeze().expect("Storage freeze must not fail");

        self.state_db
            .write_schemas(state_batch)
            .expect("DB write must not fail");
        self.native_db
            .write_schemas(native_batch)
            .expect("DB write must not fail");
    }

    pub fn get_state_db_handle(&self) -> Arc<DB> {
        self.state_db.clone()
    }

    pub fn get_native_db_handle(&self) -> Arc<DB> {
        self.native_db.clone()
    }
}

/// Creates orphan [`ProverStorage`] which just points directly to the underlying database for previous data
/// Should be used only in tests
#[cfg(feature = "test-utils")]
pub fn new_orphan_storage(path: impl AsRef<std::path::Path>) -> anyhow::Result<ProverStorage> {
    let state_db_raw = StateDB::setup_schema_db(&RocksdbConfig::new(path.as_ref(), None, None))?;
    let state_db = StateDB::new(Arc::new(state_db_raw));
    let native_db_raw = NativeDB::setup_schema_db(&RocksdbConfig::new(path.as_ref(), None, None))?;
    let native_db = NativeDB::new(Arc::new(native_db_raw));
    Ok(ProverStorage::committable_latest_version(
        state_db, native_db,
    ))
}
