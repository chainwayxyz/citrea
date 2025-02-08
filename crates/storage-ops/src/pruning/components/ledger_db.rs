use sov_db::ledger_db::SharedLedgerOps;
use tracing::debug;

/// Prune ledger
pub(crate) fn prune_ledger<DB: SharedLedgerOps>(_ledger_db: DB, up_to_block: u64) {
    debug!("Pruning Ledger, up to L2 block {}", up_to_block);
    // unimplemented!()
}
