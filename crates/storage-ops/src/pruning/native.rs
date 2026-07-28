use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use citrea_common::utils::shutdown_requested;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::schema::tables::ModuleAccessoryState;
use sov_schema_db::ScanDirection;
use tracing::info;

/// Prune native DB
pub(crate) fn prune_native_db(
    native_db: Arc<sov_schema_db::DB>,
    up_to_block: u64,
    shutdown_signal: Option<&GracefulShutdown>,
) -> anyhow::Result<()> {
    info!("Pruning native DB, up to L2 block {}", up_to_block);
    let start = Instant::now();

    // We iterate backwards (newest to oldest) so that when we see a key for the first time,
    // it's the newest version. This allows us to keep the newest version and delete older ones.
    // For versioned state (accounts, etc.): seen_keys tracks which keys we want to preserve.
    let mut iter = native_db
        .iter_with_direction::<ModuleAccessoryState>(Default::default(), ScanDirection::Backward)
        .map_err(|e| anyhow::anyhow!("Failed to create iterator for native DB pruning: {e:?}"))?;

    iter.seek_to_last();

    let mut seen_keys = HashSet::new();
    let mut keys_to_delete = vec![];

    while let Some(Ok(entry)) = iter.next() {
        if shutdown_signal.is_some_and(shutdown_requested) {
            anyhow::bail!("Shutting down pruner");
        }

        let key = &entry.key.0;
        let version = entry.key.1;

        // Skip the offchain state records for evm.code
        if key.starts_with(b"E/c/".as_slice()) {
            continue;
        }

        // AccessoryStateVec entries (blocks, transactions, receipts) need special handling:
        // - Each entry has a UNIQUE key (example: E/blocks/e\x14 for block 20, E/blocks/e\x15 for block 21)
        // - Since keys never repeat, seen_keys logic won't work,
        // - We must delete directly based on version, without checking seen_keys
        // This is different from versioned state where the SAME key appears with multiple versions.
        let patterns = [
            b"E/blocks/e".as_slice(),
            b"E/receipts/e".as_slice(),
            b"E/transactions/e".as_slice(),
        ];

        if patterns.iter().any(|prefix| key.starts_with(prefix)) {
            // All entries are stored with version = block_number + 1
            if version <= up_to_block + 1 {
                keys_to_delete.push(entry.key.clone());
            }
            continue;
        }

        // Handle other versioned entries.
        if version <= up_to_block + 1 {
            // Delete only after preserving a newer (or first-seen) version for this key.
            if seen_keys.contains(key) {
                keys_to_delete.push(entry.key.clone());
            } else {
                seen_keys.insert(key.clone());
            }
        } else {
            // Track that we've seen a recent version of this key
            seen_keys.insert(key.clone());
        }
    }

    let deletions_count = keys_to_delete.len();
    native_db
        .delete_batch::<ModuleAccessoryState>(keys_to_delete)
        .map_err(|e| anyhow::anyhow!("Failed to delete batch during native DB pruning: {e:?}"))?;

    let duration = start.elapsed();
    info!(
        "Native DB pruning completed, up_to_block={}, deletions={}, duration={}ms",
        up_to_block,
        deletions_count,
        duration.as_millis()
    );
    Ok(())
}
