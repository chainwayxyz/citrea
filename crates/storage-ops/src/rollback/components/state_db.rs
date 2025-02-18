use std::sync::Arc;

use jmt::storage::Node;
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey};
use sov_schema_db::SchemaBatch;
use tracing::{error, info};

/// Rollback state DB
#[allow(dead_code)]
pub(crate) fn rollback_state_db(state_db: Arc<sov_schema_db::DB>, down_to_block: u64) {
    info!("Rolling back state DB, down to L2 block {}", down_to_block);

    let to_version = down_to_block + 1;

    let mut indices = state_db
        .iter::<JmtNodes>()
        .expect("Tried to rollback state DB but could not obtain an iterator");

    indices.seek_to_last();

    let mut deletions = 0;

    let mut batch = SchemaBatch::new();
    for index in indices {
        let Ok(index) = index else {
            continue;
        };

        let node_key = index.key;
        let node = index.value;

        // Exit loop if we go down below the target block
        if node_key.version() < to_version {
            break;
        }

        let key_hash = match node {
            Node::Null => continue,
            Node::Internal(_) => {
                if let Err(e) = batch.delete::<JmtNodes>(&node_key) {
                    error!(
                        "Could not add JMT node deletion to schema batch operation: {:?}",
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

        if let Err(e) = batch.delete::<JmtValues>(&(key_preimage, node_key.version())) {
            error!(
                "Could not add JMT value deletion to schema batch operation: {:?}",
                e
            );
        }

        if let Err(e) = batch.delete::<JmtNodes>(&node_key) {
            error!(
                "Could not add JMT node deletion to schema batch operation: {:?}",
                e
            );
        }

        deletions += 2;
    }

    if let Err(e) = state_db.write_schemas(batch) {
        error!("Could not delete state data: {:?}", e);
    }

    info!("Rolled back {} records from state DB", deletions);
}
