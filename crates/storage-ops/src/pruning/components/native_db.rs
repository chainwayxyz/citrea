use std::sync::Arc;

use sov_db::schema::tables::ModuleAccessoryState;
use tracing::{debug, error};

/// Prune native DB
pub(crate) fn prune_native_db(native_db: Arc<sov_schema_db::DB>, up_to_block: u64) {
    debug!("Pruning native DB, up to L2 block {}", up_to_block);

    let Ok(mut iter) = native_db.iter::<ModuleAccessoryState>() else {
        return;
    };

    iter.seek_to_first();

    let mut counter = 0u32;
    let mut keys_to_delete = vec![];
    while let Some(Ok(entry)) = iter.next() {
        let version = entry.key.1;
        // The version value is always ahead of block number by one.
        if version < up_to_block + 1 {
            keys_to_delete.push(entry.key);
            counter += 1;
        }
    }

    if let Err(e) = native_db.delete_batch::<ModuleAccessoryState>(keys_to_delete) {
        error!("Failed to delete native DB entry {:?}", e);
        return;
    }

    debug!("Pruned {} native DB records", counter);
}
