use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};

pub(super) struct MigratePrunedL2Height {}

impl LedgerMigration for MigratePrunedL2Height {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("MigratePrunedL2Height".to_owned(), 1)
    }

    fn execute(&self, ledger_db: Arc<LedgerDB>) -> anyhow::Result<()> {
        let Some(mut last_pruned_height) = ledger_db.get_last_pruned_l2_height()? else {
            // No need to do any migration
            return Ok(());
        };

        // Example
        last_pruned_height += 10;
        ledger_db.set_last_pruned_l2_height(last_pruned_height)?;

        Ok(())
    }
}
