use std::sync::Arc;

use sov_schema_db::transaction::DbTransaction;
use sov_schema_db::{SchemaBatch, DB};

use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::{LastPrunedL2Height, ModuleAccessoryState, NATIVE_TABLES};
use crate::schema::types::StateKeyRef;

/// Specifies a particular version of the Accessory state.
pub type Version = u64;

/// Typesafe wrapper for Data, that is not part of the provable state
/// TODO: Rename to AccessoryDb
#[derive(Debug, Clone)]
pub struct NativeDB {
    /// Pointer to [`DbTransaction`] for up to date state
    db: Arc<DbTransaction>,
}

impl NativeDB {
    /// NativeDB path suffix
    pub const DB_PATH_SUFFIX: &'static str = "native";
    const DB_NAME: &'static str = "native-db";

    /// Initialize [`sov_schema_db::DB`] that matches tables and columns for NativeDB
    pub fn setup_schema_db(cfg: &RocksdbConfig) -> anyhow::Result<sov_schema_db::DB> {
        let raw_options = cfg.as_raw_options(false);
        let path = cfg.path.join(Self::DB_PATH_SUFFIX);
        sov_schema_db::DB::open(
            path,
            Self::DB_NAME,
            NATIVE_TABLES.iter().copied(),
            &raw_options,
        )
    }
    /// Convert it to [`SchmeaBatch`] which cannot be edited anymore
    pub fn freeze(self) -> anyhow::Result<SchemaBatch> {
        let inner = Arc::into_inner(self.db).ok_or(anyhow::anyhow!(
            "NativeDB underlying DbTransaction has more than 1 strong references"
        ))?;
        Ok(inner.into())
    }
}

impl NativeDB {
    /// Creating instance of [`NativeDB`] from [`Arc<DB>`]
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            db: Arc::new(DbTransaction::new(db)),
        }
    }

    /// Queries for a value in the [`NativeDB`], given a key.
    pub fn get_value_option(
        &self,
        key: StateKeyRef,
        version: Version,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let found = self
            .db
            .get_prev::<ModuleAccessoryState>(&(key.to_vec(), version))?;
        match found {
            Some(((found_key, found_version), value)) => {
                if found_key == key {
                    anyhow::ensure!(found_version <= version, "Bug! iterator isn't returning expected values. expected a version <= {version:} but found {found_version:}");
                    Ok(value)
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Get the last pruned l2 height
    pub fn get_last_pruned_l2_height(&self) -> anyhow::Result<Option<u64>> {
        let found = self.db.get_prev::<LastPrunedL2Height>(&())?;
        match found {
            Some((_, value)) => Ok(Some(value)),
            None => Ok(None),
        }
    }

    /// Sets a sequence of key-value pairs in the [`NativeDB`]. The write is atomic.
    pub fn set_values(
        &self,
        key_value_pairs: impl IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
        version: Version,
    ) -> anyhow::Result<()> {
        let mut batch = SchemaBatch::default();
        for (key, value) in key_value_pairs {
            batch.put::<ModuleAccessoryState>(&(key, version), &value)?;
        }
        self.db.write_many(batch)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> NativeDB {
        let tmpdir = tempfile::tempdir().unwrap();
        let db = NativeDB::setup_schema_db(&RocksdbConfig::new(tmpdir.path(), None, None)).unwrap();
        NativeDB::new(Arc::new(db))
    }

    #[test]
    fn get_after_set() {
        let db = setup_db();

        let key = b"foo".to_vec();
        let value = b"bar".to_vec();
        db.set_values(vec![(key.clone(), Some(value.clone()))], 0)
            .unwrap();
        assert_eq!(db.get_value_option(&key, 0).unwrap(), Some(value.clone()));
        let value2 = b"bar2".to_vec();
        db.set_values(vec![(key.clone(), Some(value2.clone()))], 1)
            .unwrap();
        assert_eq!(db.get_value_option(&key, 0).unwrap(), Some(value));
    }

    #[test]
    fn get_after_delete() {
        let db = setup_db();

        let key = b"deleted".to_vec();
        db.set_values(vec![(key.clone(), None)], 0).unwrap();
        assert_eq!(db.get_value_option(&key, 0).unwrap(), None);
    }

    #[test]
    fn get_nonexistent() {
        let db = setup_db();

        let key = b"spam".to_vec();
        assert_eq!(db.get_value_option(&key, 0).unwrap(), None);
    }
}
