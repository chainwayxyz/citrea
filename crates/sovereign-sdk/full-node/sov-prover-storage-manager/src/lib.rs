use std::sync::Arc;

use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use sov_schema_db::{SchemaBatch, DB};
pub use sov_state::ProverStorage;

pub struct ProverStorageManager {
    state_db: Arc<DB>,
    native_db: Arc<DB>,
    next_version: u64,
}

impl ProverStorageManager {
    fn with_db_handles(state_db: Arc<DB>, native_db: Arc<DB>, next_version: u64) -> Self {
        Self {
            state_db,
            native_db,
            next_version,
        }
    }

    /// Create new [`ProverStorageManager`] from state config
    pub fn new(config: sov_state::config::Config, next_version: u64) -> anyhow::Result<Self> {
        let rocksdb_config =
            RocksdbConfig::new(config.path.as_path(), config.db_max_open_files, None);
        let state_db = Arc::new(StateDB::setup_schema_db(&rocksdb_config)?);
        let native_db = Arc::new(NativeDB::setup_schema_db(&rocksdb_config)?);
        Ok(Self::with_db_handles(state_db, native_db, next_version))
    }

    pub fn create_storage_snapshot(&self, l2_height: u64) -> ProverStorage {
        assert!(
            l2_height <= self.next_version,
            "Got l2 height higher than last version"
        );
        let state_db = StateDB::new(self.state_db.clone());
        let native_db = NativeDB::new(self.native_db.clone());
        // TODO: l2_height as version??
        ProverStorage::with_db_handles(state_db, native_db, l2_height)
    }

    pub fn create_storage(&self) -> ProverStorage {
        self.create_storage_snapshot(self.next_version)
    }

    pub fn finalize_storage(&self, state_batch: SchemaBatch, native_batch: SchemaBatch) {
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
    Ok(ProverStorage::with_db_handles(state_db, native_db, 0))
}

// TODO: write tests
