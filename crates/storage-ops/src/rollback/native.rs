use std::sync::Arc;

use sov_db::schema::tables::ModuleAccessoryState;
use sov_schema_db::ScanDirection;
use tracing::{debug, error};

/// Rollback native DB
pub(crate) fn rollback_native_db(native_db: Arc<sov_schema_db::DB>, target_version: u64) {
    debug!(
        "Rolling back native DB, down to L2 block {}",
        target_version
    );

    let Ok(mut iter) = native_db
        .iter_with_direction::<ModuleAccessoryState>(Default::default(), ScanDirection::Backward)
    else {
        return;
    };

    iter.seek_to_last();

    let mut counter = 0u32;
    let mut keys_to_delete = vec![];
    while let Some(Ok(entry)) = iter.next() {
        let version = entry.key.1;
        // The version value is always ahead of block number by one.
        if version > target_version {
            keys_to_delete.push(entry.key);
            counter += 1;
        }
    }

    if let Err(e) = native_db.delete_batch::<ModuleAccessoryState>(keys_to_delete) {
        error!("Failed to delete native DB entry {:?}", e);
        return;
    }

    let _ = native_db.flush();

    debug!("Rolled back {} native DB records", counter);
}
