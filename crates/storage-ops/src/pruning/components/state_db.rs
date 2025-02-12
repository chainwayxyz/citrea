use std::collections::HashSet;
use std::iter::Peekable;
use std::sync::Arc;

use jmt::storage::{Node, StaleNodeIndex};
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey, StaleNodes};
use sov_schema_db::{ScanDirection, SchemaBatch, SchemaIterator, DB};
use tracing::{debug, error, info, trace};

struct StaleNodeIndicesByVersionIterator<'a> {
    inner: Peekable<SchemaIterator<'a, StaleNodes>>,
    up_to_version: u64,
}

impl<'a> StaleNodeIndicesByVersionIterator<'a> {
    fn new(db: &'a DB, up_to_version: u64) -> anyhow::Result<Self> {
        let mut iter = db.iter::<StaleNodes>()?;
        iter.seek_to_first();

        Ok(Self {
            inner: iter.peekable(),
            up_to_version,
        })
    }

    fn next_result(&mut self) -> anyhow::Result<Option<Vec<StaleNodeIndex>>> {
        match self.inner.next().transpose()? {
            None => Ok(None),
            Some(iter_output) => {
                let index = iter_output.key;
                let version = index.stale_since_version;
                if version > self.up_to_version {
                    return Ok(None);
                }

                let mut indices = vec![index];
                while let Some(res) = self.inner.peek() {
                    if let Ok(iter_output_ref) = res {
                        let index_ref = iter_output_ref.key.clone();

                        if index_ref.stale_since_version != version {
                            break;
                        }
                    }

                    let iter_output = self.inner.next().transpose()?.expect("Should be Some.");
                    indices.push(iter_output.key);
                }

                Ok(Some(indices))
            }
        }
    }
}

impl<'a> Iterator for StaleNodeIndicesByVersionIterator<'a> {
    type Item = anyhow::Result<Vec<StaleNodeIndex>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_result().transpose()
    }
}

/// Prune state DB
pub(crate) fn prune_state_db(state_db: Arc<sov_schema_db::DB>, to_block: u64) {
    info!("Pruning state DB, up to L2 block {}", to_block);

    let Ok(indices) = StaleNodeIndicesByVersionIterator::new(&state_db, to_block + 1) else {
        error!("Could not read stale nodes");
        return;
    };

    let indices = indices
        .into_iter()
        .flatten()
        .flatten()
        .collect::<HashSet<_>>();

    if indices.is_empty() {
        debug!("State: Nothing to prune");
        return;
    }

    let mut state_keys_deleted = 0;
    let mut state_values_deleted = 0;

    let mut batch = SchemaBatch::new();
    for index in indices {
        // Skip genesis keys altogether.
        if index.node_key.version() == 1 {
            continue;
        }

        // Based on the `NodeKey` for the stale node, we'd like to find the actual key
        // to identify the values saved for that specific key.
        let node = match state_db.get::<JmtNodes>(&index.node_key) {
            Ok(Some(node)) => node,
            _ => {
                error!("Failed to get Jmt node");
                continue;
            }
        };

        let stale_since_version = index.stale_since_version;
        let key_hash = match node {
            Node::Null | Node::Internal(_) => continue,
            Node::Leaf(leaf) => leaf.key_hash(),
        };

        let key = match state_db.get::<KeyHashToKey>(&key_hash.0) {
            Ok(Some(key)) => key,
            _ => {
                error!("Could not read key from key hash");
                continue;
            }
        };

        // println!(
        //     "Deleting from {} - to {}",
        //     from_block + 1,
        //     stale_since_version - 1
        // );
        // if let Err(e) = state_db.delete_range::<JmtValues>(
        //     &(key.clone(), from_block + 1),
        //     &(key.clone(), stale_since_version - 1),
        // ) {
        //     error!("Could not delete JmtValues range: {:?}", e);
        // }

        state_keys_deleted += 1;

        // println!(
        //     "DELETING Node key: {:?} up to version {}",
        //     String::from_utf8_lossy(&key),
        //     to_block
        // );
        // We have the key, now we should find how many values of which versions we have.
        let mut values_iter = match state_db
            .iter_with_direction::<JmtValues>(Default::default(), ScanDirection::Backward)
        {
            Ok(iter) => iter,
            Err(e) => {
                error!("Could not create an iterator for JmtValues: {:?}", e);
                continue;
            }
        };
        if let Err(e) = values_iter.seek(&(key.clone(), stale_since_version)) {
            error!("Failed to seek on JmtValues iterator: {:?}", e);
            continue;
        }

        let mut value_keys = vec![];
        for value_key in values_iter {
            if let Ok(value_key) = value_key {
                if value_key.key.0 != key {
                    break;
                }
                if value_key.key.0 == key
                    && value_key.key.1 <= stale_since_version
                    && stale_since_version <= to_block
                {
                    // println!(
                    //     "Node key: {:?} stale since: {}",
                    //     value_key.key, stale_since_version
                    // );
                    value_keys.push(value_key.key);
                }
            }
        }
        value_keys.sort_by_key(|(_, version)| *version);

        let keys_count = value_keys.len();
        if keys_count <= 1 {
            trace!(
                "Only one value for a key {:?} is found, skipping",
                hex::encode(key)
            );
            continue;
        }

        state_values_deleted += keys_count - 1;

        // Delete all values BUT the last one.
        for (value_key, value_version) in &value_keys {
            if let Err(e) = batch.delete::<JmtValues>(&(value_key.clone(), *value_version)) {
                error!(
                    "Could not add JMT value deletion to schema batch operation: {:?}",
                    e
                );
            }
        }

        if let Err(e) = batch.delete::<JmtNodes>(&index.node_key) {
            error!(
                "Could not add JMT node deletion to schema batch operation: {:?}",
                e
            );
        }

        if let Err(e) = batch.delete::<StaleNodes>(&index) {
            error!(
                "Could not add stale node deletion to schema batch operation: {:?}",
                e
            );
        }
    }

    if let Err(e) = state_db.write_schemas(batch) {
        error!("Could not delete state data: {:?}", e);
    }

    info!(
        "Pruned {} keys and {} values from DB records",
        state_keys_deleted, state_values_deleted
    );
}
