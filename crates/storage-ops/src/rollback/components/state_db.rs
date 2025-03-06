use std::sync::Arc;

use jmt::storage::{Node, NodeKey};
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey};
use sov_schema_db::{ScanDirection, SchemaBatch};
use tracing::{error, info};

/// Rollback state DB
pub(crate) fn rollback_state_db(state_db: Arc<sov_schema_db::DB>, down_to_block: u64) {
    info!("Rolling back state DB, down to L2 block {}", down_to_block);

    let target_version = down_to_block + 1;

    let mut indices = state_db
        .iter_with_direction::<JmtNodes>(Default::default(), ScanDirection::Backward)
        .expect("Tried to rollback state DB but could not obtain an iterator");

    indices.seek_to_last();
    let mut iter = indices.peekable();

    let mut deletions = 0;

    // Since deleting JmtNodes results in degrading the performance
    // of seek on JmtNode table, we'd like to delete those values in ranges
    // which will record a single delete on multiple records resulting in
    // faster seeks.
    let mut jmt_nodes_range_start = None;
    let mut jmt_nodes_range_end = None;

    let mut batch = SchemaBatch::new();
    while let Some(index) = iter.next() {
        let Ok(index) = index else {
            break;
        };

        if jmt_nodes_range_start.is_none() {
            jmt_nodes_range_start = Some(index.key.clone());
        }

        let node_key = index.key;
        let node = index.value;

        // Always set this value because if we break below,
        // the range deletion is non-inclusive.
        if jmt_nodes_range_start != Some(node_key.clone()) {
            jmt_nodes_range_end = iter
                .peek()
                .map(|i| i.as_ref().ok().map(|inner| inner.key.clone()))
                .flatten();
        }

        // Exit loop if we go down below the target block
        if node_key.version() <= target_version {
            break;
        }
        let key_hash = match node {
            Node::Null => {
                // Range consecutiveness is broken, so we delete the range here.
                if let Err(e) = delete_jmt_nodes_range(
                    &state_db,
                    jmt_nodes_range_start.clone(),
                    jmt_nodes_range_end.clone(),
                ) {
                    error!("Could not delete JMTNodes range {:?}", e);
                }
                jmt_nodes_range_start = None;
                jmt_nodes_range_end = None;
                continue;
            }
            Node::Internal(_) => {
                if let Err(e) = delete_jmt_nodes_range(
                    &state_db,
                    jmt_nodes_range_start.clone(),
                    jmt_nodes_range_end.clone(),
                ) {
                    error!("Could not delete JMTNodes range {:?}", e);
                }
                jmt_nodes_range_start = None;
                jmt_nodes_range_end = None;
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

        // if let Err(e) = batch.delete::<JmtNodes>(&node_key) {
        //     error!(
        //         "Could not add JMT node deletion to schema batch operation: {:?}",
        //         e
        //     );
        // }

        deletions += 2;
    }

    if let Err(e) = delete_jmt_nodes_range(&state_db, jmt_nodes_range_start, jmt_nodes_range_end) {
        error!("Could not delete JMTNodes range {:?}", e);
        return;
    }

    if let Err(e) = state_db.write_schemas(batch) {
        error!("Could not delete state data: {:?}", e);
    }

    let _ = state_db.flush();

    info!("Rolled back {} records from state DB", deletions);
}

fn delete_jmt_nodes_range(
    state_db: &sov_schema_db::DB,
    start: Option<NodeKey>,
    end: Option<NodeKey>,
) -> anyhow::Result<()> {
    let Some(start) = start else {
        return Ok(());
    };
    let Some(end) = end else {
        return Ok(());
    };
    if start == end {
        return Ok(());
    }
    // Start from end all the way up to start since we seek in reverse order above
    let (start, end) = (end, start);

    state_db.delete_range::<JmtNodes>(&start, &end)?;
    Ok(())
}
