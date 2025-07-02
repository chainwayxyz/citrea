use std::sync::Arc;

use jmt::storage::Node;
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey};
use sov_schema_db::{ScanDirection, SchemaBatch};
use tracing::{error, info};

pub(crate) fn rollback_state_db(state_db: Arc<sov_schema_db::DB>, target_version: u64) {
    info!(
        "Rolling back state DB, down to target version {}",
        target_version
    );

    let mut indices = state_db
        .iter_with_direction::<JmtNodes>(Default::default(), ScanDirection::Backward)
        .expect("Tried to rollback state DB but could not obtain an iterator");

    indices.seek_to_last();

    let mut iter = indices.peekable();

    let last_version = iter.peek().and_then(|r| r.as_ref().ok());
    let last_version = last_version.unwrap().key.version() + 1;

    let mut deletions = 0;

    let mut batch = SchemaBatch::new();
    for node in iter {
        let Ok(node) = node else {
            break;
        };

        let node_key = node.key;
        let node_value = node.value;

        // Exit loop if we go down below the target block
        if node_key.version() <= target_version {
            break;
        }

        let key_hash = match node_value {
            Node::Null | Node::Internal(_) => {
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

        deletions += 2;
    }

    if let Err(e) = state_db.write_schemas(batch) {
        error!("Could not delete state data: {:?}", e);
    }

    let mut last_version_output = Vec::with_capacity(8);
    let last_version_bytes = last_version.to_be_bytes();
    last_version_output.extend_from_slice(&last_version_bytes);

    let mut target_version_output = Vec::with_capacity(8);
    // Delete starting from/including the block AFTER `down_to_block`.
    let target_version_bytes = (target_version + 1).to_be_bytes();
    target_version_output.extend_from_slice(&target_version_bytes);

    if let Err(e) = state_db
        .delete_range_raw::<JmtNodes>(target_version_bytes.to_vec(), last_version_bytes.to_vec())
    {
        error!(
            "Could not delete JmtNodes range {:?} to {:?}: {:?}",
            target_version + 1,
            last_version,
            e
        );
    }

    let _ = state_db.flush();

    info!("Rolled back {} records from state DB", deletions);
}
