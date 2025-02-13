use std::sync::Arc;

use sov_schema_db::DB;
use tables::prune_soft_confirmations_by_number;
use tracing::{debug, error};

use crate::pruning::types::PruningNodeType;

mod tables;

/// Prune ledger
pub(crate) fn prune_ledger(node_type: PruningNodeType, ledger_db: Arc<DB>, up_to_block: u64) {
    debug!("Pruning Ledger, up to L2 block {}", up_to_block);

    if let Err(e) = prune_shared_tables(&ledger_db) {
        error!("Failed to prune shared ledger tables: {:?}", e);
        return;
    }
}

fn prune_shared_tables(ledger_db: &DB, up_to_block: u64) -> anyhow::Result<()> {
    prune_soft_confirmations_by_number(ledger_db)?;

    Ok(())
}
