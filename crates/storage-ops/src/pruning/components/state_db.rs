use std::sync::Arc;

use jmt::storage::Node;
use sov_db::schema::tables::{JmtNodes, JmtValues, KeyHashToKey, StaleNodes};
use sov_schema_db::SchemaBatch;
use tracing::{error, info};

/// Prune state DB
pub(crate) fn prune_state_db(state_db: Arc<sov_schema_db::DB>, to_block: u64) {
    info!("Pruning state DB, up to L2 block {}", to_block);

    let to_version = to_block + 1;

    let mut indices = state_db.iter::<StaleNodes>().expect("should get iter");

    indices.seek_to_first();

    // if indices.is_empty() {
    //     error!("State: Nothing to prune");
    //     return;
    // }

    let mut deletions = 0;

    let mut batch = SchemaBatch::new();
    while let Some(index) = indices.next() {
        let index = index.unwrap();
        let index = index.key;

        // TODO: maybe don't do this
        if index.node_key.version() == 1 {
            continue;
        }

        if index.stale_since_version > to_version {
            // if we started to get bigger versions than target block
            // break out of the loop
            break;
        }

        // println!("Deleteing stale node: {:?}", index);

        // Based on the `NodeKey` for the stale node, we'd like to find the actual key
        // to identify the values saved for that specific key.
        let node = match state_db.get::<JmtNodes>(&index.node_key) {
            Ok(Some(node)) => node,
            _ => {
                panic!("Failed to get Jmt node even though it was found in stale nodes");
            }
        };

        let key_hash = match node {
            // TODO: check if we can delete internal nodes?
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

        // println!("Deleting state key: {}", hex::encode(&key_hash.0));

        let key_preimage = match state_db.get::<KeyHashToKey>(&key_hash.0) {
            Ok(Some(key)) => key,
            _ => {
                error!("Could not read key from key hash");
                continue;
            }
        };
        // println!(
        //     "Deleting state key: {} version: {} raw key: {:?}",
        //     std::string::String::from_utf8_lossy(&key_preimage),
        //     index.node_key.version(),
        //     key_preimage
        // );
        let mut x = state_db.iter::<JmtValues>().unwrap();

        x.seek(&(key_preimage.clone(), index.node_key.version()))
            .unwrap();

        let _ = x.next().expect("Should be in db");

        let next_in_iter = x.next();

        if next_in_iter.is_none() {
            println!("Got the last key in db?");
            // if let Err(e) = batch.delete::<StaleNodes>(&index) {
            //     error!(
            //         "Could not add stale node deletion to schema batch operation: {:?}",
            //         e
            //     );
            // }
            continue;
        }

        let (key, _version) = &next_in_iter.unwrap().unwrap().key;

        if *key != key_preimage {
            // println!("No bigger version for that key!");

            // This means there was no bigger version for that key
            // This is probably a bug in the JMT crate
            // if let Err(e) = batch.delete::<StaleNodes>(&index) {
            //     error!(
            //         "Could not add stale node deletion to schema batch operation: {:?}",
            //         e
            //     );
            // }
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
