use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::LedgerDB;

/// Table removal migration
/// tables BatchByNumber and SlotByNumber are removed
pub(crate) struct MigrateBatchAndSlotByNumber {}

impl LedgerMigration for MigrateBatchAndSlotByNumber {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("MigrateBatchAndSlotByNumber".to_owned(), 1)
    }

    fn execute(
        &self,
        _ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let batch_by_number = "BatchByNumber".to_owned();
        let slot_by_number = "SlotByNumber".to_owned();

        tables_to_drop.push(batch_by_number);
        tables_to_drop.push(slot_by_number);
        Ok(())
    }
}
