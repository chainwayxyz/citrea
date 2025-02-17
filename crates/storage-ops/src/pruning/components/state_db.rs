use std::sync::Arc;

use jmt::storage::Node;
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey, StaleNodes};
use sov_schema_db::SchemaBatch;
use tracing::{error, info};

/// Prune state DB
#[allow(dead_code)]
pub(crate) fn prune_state_db(state_db: Arc<sov_schema_db::DB>, to_block: u64) {
    info!("Pruning state DB, up to L2 block {}", to_block);

    let to_version = to_block + 1;

    let mut indices = state_db
        .iter::<StaleNodes>()
        .expect("Tried to prune state DB but could not obtain an iterator");

    indices.seek_to_first();

    let mut deletions = 0;

    let mut batch = SchemaBatch::new();
    for index in indices {
        let Ok(index) = index else {
            continue;
        };

        let index = index.key;

        // TODO: We currently have this check to prevent pruning index nodes
        // for the genesis block. However, since this is reported as stale
        // we need to double check if these keys are prunable as well or not.
        if index.node_key.version() == 1 {
            continue;
        }

        if index.stale_since_version > to_version {
            // if we started to get bigger versions than target block
            // break out of the loop
            break;
        }

        // Based on the `NodeKey` for the stale node, we'd like to find the actual key
        // to identify the values saved for that specific key.
        let node = match state_db.get::<JmtNodes>(&index.node_key) {
            Ok(Some(node)) => node,
            _ => {
                panic!("Failed to get Jmt node even though it was found in stale nodes");
            }
        };

        let key_hash = match node {
            Node::Null => continue,
            Node::Internal(_) => {
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

                deletions += 1;
                continue;
            }
            Node::Leaf(leaf) => leaf.key_hash(),
        };

        let key_preimage = match state_db.get::<KeyHashToKey>(&key_hash.0) {
            Ok(Some(key)) => key,
            _ => {
                error!("Could not read key from key hash");
                continue;
            }
        };

        let mut values_iter = match state_db.iter::<JmtValues>() {
            Ok(iter) => iter,
            Err(e) => {
                error!("Coult not iterate JmtValues: {:?}", e);
                continue;
            }
        };

        if let Err(e) = values_iter.seek(&(key_preimage.clone(), index.node_key.version())) {
            error!("Could not seek on JmtValues iterator: {:?}", e);
            continue;
        }

        if values_iter.next().is_none() {
            panic!("The JmtValue key does not exist in DB");
        }

        // Check if a value that has a larger key version exists
        let Ok(next_larger_version_value) = values_iter.next().transpose() else {
            continue;
        };

        let Some(iterator_output) = next_larger_version_value else {
            continue;
        };

        let (key, _version) = iterator_output.key;

        if *key != key_preimage {
            // TODO
            // This means there was no bigger version for that key
            // This is probably a bug in the JMT crate
            if let Err(e) = batch.delete::<StaleNodes>(&index) {
                error!(
                    "Could not add stale node deletion to schema batch operation: {:?}",
                    e
                );
            }
            continue;
        }

        if let Err(e) = batch.delete::<JmtValues>(&(key_preimage, index.node_key.version())) {
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

        deletions += 2;
    }

    if let Err(e) = state_db.write_schemas(batch) {
        error!("Could not delete state data: {:?}", e);
    }

    info!("Pruned {} records from state DB", deletions);
}
