#![allow(missing_docs)]
use std::sync::Arc;

use sov_rollup_interface::mmr::MMRNative;
use sov_schema_db::DB;
use tracing::instrument;

use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::{MMRNodes, MMR_TABLES};

#[derive(Clone, Debug)]
pub struct MmrDB {
    db: Arc<DB>,
}

impl MmrDB {
    const DB_PATH_SUFFIX: &'static str = "mmr";
    const DB_NAME: &'static str = "mmr-db";

    /// Initialize [`sov_schema_db::DB`] that should be used by snapshots.
    pub fn setup_schema_db(cfg: &RocksdbConfig) -> anyhow::Result<sov_schema_db::DB> {
        let raw_options = cfg.as_raw_options(false);
        let mmr_db_path = cfg.path.join(Self::DB_PATH_SUFFIX);
        sov_schema_db::DB::open(
            mmr_db_path,
            Self::DB_NAME,
            MMR_TABLES.iter().copied(),
            &raw_options,
        )
    }

    /// Open a [`MMRDB`] (backed by RocksDB) at the specified path.
    #[instrument(level = "trace", skip_all, err)]
    pub fn new(cfg: &RocksdbConfig) -> Result<Self, anyhow::Error> {
        let path = cfg.path.join(Self::DB_PATH_SUFFIX);
        let raw_options = cfg.as_raw_options(false);
        let tables: Vec<_> = MMR_TABLES.iter().map(|e| e.to_string()).collect();
        let inner = DB::open(path, Self::DB_NAME, tables, &raw_options)?;

        Ok(Self {
            db: Arc::new(inner),
        })
    }

    /// Put the preimage of a hashed key into the database. Note that the preimage is not checked for correctness,
    /// since the DB is unaware of the hash function used by the JMT.
    pub fn put(&self, mmr_native: MMRNative) -> Result<(), anyhow::Error> {
        self.db.put::<MMRNodes>(&(), &mmr_native)
    }

    /// Get an optional value from the database, given a version and a key hash.
    pub fn get(&self) -> anyhow::Result<Option<MMRNative>> {
        self.db.get::<MMRNodes>(&())
    }
}
