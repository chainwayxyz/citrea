use std::collections::BTreeSet;
use std::sync::Arc;

use jmt::storage::{HasPreimage, StaleNodeIndex, TreeReader, TreeWriter};
use jmt::{KeyHash, Version};
use sov_schema_db::transaction::DbTransaction;
use sov_schema_db::{SchemaBatch, DB};

use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::{JmtNodes, JmtValues, KeyHashToKey, StaleNodes, STATE_TABLES};
use crate::schema::types::StateKeyRef;

/// A typed wrapper around the db for storing rollup state. Internally,
/// this is roughly just an [`Arc<sov_schema_db::DB>`] with pointer to list of non-finalized writes.
///
/// StateDB implements several convenience functions for state storage -
/// notably the [`TreeReader`] and [`TreeWriter`] traits.
#[derive(Debug, Clone)]
pub struct StateDB {
    /// The underlying [`DbTransaction`] that plays as local cache and pointer to [`sov_schema_db::DB`]
    db: Arc<DbTransaction>,
}

impl StateDB {
    /// StateDB path suffix
    pub const DB_PATH_SUFFIX: &'static str = "state";
    const DB_NAME: &'static str = "state-db";

    /// Initialize [`DB`] that should be globally used
    pub fn setup_schema_db(cfg: &RocksdbConfig) -> anyhow::Result<sov_schema_db::DB> {
        let raw_options = cfg.as_raw_options(false);
        let state_db_path = cfg.path.join(Self::DB_PATH_SUFFIX);
        sov_schema_db::DB::open(
            state_db_path,
            Self::DB_NAME,
            STATE_TABLES.iter().copied(),
            &raw_options,
        )
    }

    /// Convert it to [`SchemaBatch`] which cannot be edited anymore. Takes ownership of the
    /// cached transaction writes.
    pub fn freeze(self) -> anyhow::Result<SchemaBatch> {
        let inner = Arc::into_inner(self.db).ok_or(anyhow::anyhow!(
            "StateDB underlying DbTransaction has more than 1 strong references"
        ))?;
        Ok(inner.into())
    }

    /// Returns the next expected version from the state storage. Starts from 1.
    pub fn next_version(&self) -> Version {
        let last_key_value = self
            .db
            .get_largest::<JmtNodes>()
            .expect("Get largest db call should not fail");
        let largest_version = last_key_value.map(|(k, _)| k.version());

        largest_version
            .unwrap_or_default()
            .checked_add(1)
            .expect("JMT Version overflow. It is over.")
    }
}

impl StateDB {
    /// Creating instance of [`StateDB`] from [`Arc<DB>`]
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            db: Arc::new(DbTransaction::new(db)),
        }
    }

    /// Put the preimage of a hashed key into the database. Note that the preimage is not checked for correctness,
    /// since the DB is unaware of the hash function used by the JMT.
    pub fn put_preimages<'a>(
        &self,
        items: impl IntoIterator<Item = (KeyHash, StateKeyRef<'a>)>,
    ) -> Result<(), anyhow::Error> {
        let mut batch = SchemaBatch::new();
        for (key_hash, key) in items.into_iter() {
            batch.put::<KeyHashToKey>(&key_hash.0, &key.to_vec())?;
        }
        self.db.write_many(batch)?;
        Ok(())
    }

    /// Get an optional value from the database, given a version and a key hash.
    pub fn get_value_option_by_key(
        &self,
        version: Version,
        key: StateKeyRef,
    ) -> anyhow::Result<Option<jmt::OwnedValue>> {
        let found = self.db.get_prev::<JmtValues>(&(&key, version))?;
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

    /// Record stale nodes in state
    pub fn set_stale_nodes(&self, stale_nodes: &BTreeSet<StaleNodeIndex>) -> anyhow::Result<()> {
        let mut batch = SchemaBatch::new();
        for index in stale_nodes {
            batch.put::<StaleNodes>(index, &())?;
        }
        self.db.write_many(batch)?;
        Ok(())
    }
}

impl TreeReader for StateDB {
    fn get_node_option(
        &self,
        node_key: &jmt::storage::NodeKey,
    ) -> anyhow::Result<Option<jmt::storage::Node>> {
        self.db.read::<JmtNodes>(node_key)
    }

    fn get_value_option(
        &self,
        version: Version,
        key_hash: KeyHash,
    ) -> anyhow::Result<Option<jmt::OwnedValue>> {
        if let Some(key) = self.db.read::<KeyHashToKey>(&key_hash.0)? {
            self.get_value_option_by_key(version, &key)
        } else {
            Ok(None)
        }
    }

    fn get_rightmost_leaf(
        &self,
    ) -> anyhow::Result<Option<(jmt::storage::NodeKey, jmt::storage::LeafNode)>> {
        todo!("StateDB does not support [`TreeReader::get_rightmost_leaf`] yet")
    }
}

impl TreeWriter for StateDB {
    fn write_node_batch(&self, node_batch: &jmt::storage::NodeBatch) -> anyhow::Result<()> {
        let mut batch = SchemaBatch::new();
        for (node_key, node) in node_batch.nodes() {
            batch.put::<JmtNodes>(node_key, node)?;
        }

        for ((version, key_hash), value) in node_batch.values() {
            let key_preimage =
                self.db
                    .read::<KeyHashToKey>(&key_hash.0)?
                    .ok_or(anyhow::format_err!(
                        "Could not find preimage for key hash {key_hash:?}. Has `StateDB::put_preimage` been called for this key?"
                    ))?;
            batch.put::<JmtValues>(&(key_preimage, *version), value)?;
        }
        self.db.write_many(batch)?;
        Ok(())
    }
}

impl HasPreimage for StateDB {
    fn preimage(&self, key_hash: KeyHash) -> anyhow::Result<Option<Vec<u8>>> {
        self.db.read::<KeyHashToKey>(&key_hash.0)
    }
}

#[cfg(test)]
mod state_db_tests {
    use std::sync::Arc;

    use jmt::storage::{NodeBatch, TreeReader, TreeWriter};
    use jmt::KeyHash;

    use super::StateDB;
    use crate::rocks_db_config::RocksdbConfig;

    #[test]
    fn test_simple() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db = StateDB::setup_schema_db(&RocksdbConfig::new(tmpdir.path(), None, None)).unwrap();

        let db = StateDB::new(Arc::new(db));
        let key_hash = KeyHash([1u8; 32]);
        let key = vec![2u8; 100];
        let value = [8u8; 150];

        db.put_preimages(vec![(key_hash, key.as_slice())]).unwrap();
        let mut batch = NodeBatch::default();
        batch.extend(vec![], vec![((0, key_hash), Some(value.to_vec()))]);
        db.write_node_batch(&batch).unwrap();

        let found = db.get_value(0, key_hash).unwrap();
        assert_eq!(found, value);

        let found = db.get_value_option_by_key(0, &key).unwrap().unwrap();
        assert_eq!(found, value);
    }
}
