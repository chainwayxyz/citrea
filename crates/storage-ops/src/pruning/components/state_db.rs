use std::iter::Peekable;
use std::sync::Arc;

use jmt::storage::{Node, StaleNodeIndex};
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey, StaleNodes};
use sov_schema_db::{SchemaBatch, SchemaIterator, DB};
use tracing::{debug, error};

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
pub(crate) fn prune_state_db(state_db: Arc<sov_schema_db::DB>, up_to_block: u64) {
    debug!("Pruning state DB, up to L2 block {}", up_to_block);

    let Ok(indices) = StaleNodeIndicesByVersionIterator::new(&state_db, up_to_block + 1) else {
        error!("Could not read stale nodes");
        return;
    };

    let indices = indices.into_iter().flatten().flatten().collect::<Vec<_>>();

    if indices.is_empty() {
        debug!("State: Nothing to prune");
        return;
    }

    let count = indices.len();

    let mut batch = SchemaBatch::new();
    for index in indices {
        if index.node_key.version() == 1 {
            continue;
        }
        let node = match state_db.get::<JmtNodes>(&index.node_key) {
            Ok(Some(node)) => node,
            _ => {
                error!("Failed to get Jmt node");
                continue;
            }
        };

        let version = index.node_key.version();
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

        if let Err(e) = batch.delete::<JmtValues>(&(key, version)) {
            error!(
                "Could not add JMT value deletion to schema batch operation: {:?}",
                e
            );
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

    debug!("Pruned {} state DB records", count);
}
