use std::sync::Arc;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::LedgerDB;
use tracing::info;

/// Migration to drop pending sequencer commitments table
pub struct DropPendingCommitments;

impl LedgerMigration for DropPendingCommitments {
    fn identifier(&self) -> (String, u64) {
        ("drop_pending_commitments".to_string(), 1)
    }

    fn execute(
        &self,
        _ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let table_name = "PendingSequencerCommitment";
        tables_to_drop.push(table_name.to_string());
        info!("Removing table '{}'", table_name);
        Ok(())
    }
}
