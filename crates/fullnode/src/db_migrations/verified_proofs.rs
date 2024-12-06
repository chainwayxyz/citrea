use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::LedgerDB;

/// Table name change migration
/// table name "VerifiedProofsBySlotNumber" is now "VerifiedBatchProofsBySlotNumber"
pub(crate) struct MigrateVerifiedProofsBySlotNumber {}

// Name of the schema was changed from VerifiedProofsBySlotNumber to VerifiedBatchProofsBySlotNumber
impl LedgerMigration for MigrateVerifiedProofsBySlotNumber {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("MigrateVerifiedProofsBySlotNumber".to_owned(), 1)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let from = "VerifiedProofsBySlotNumber";
        let to = "VerifiedBatchProofsBySlotNumber";

        let migrate_from_handle = ledger_db.get_cf_handle(from)?;

        let migrate_from_iterator = ledger_db.get_iterator_for_cf(migrate_from_handle, None)?;

        let migrate_to_handle = ledger_db.get_cf_handle(to)?;

        // Insert key value pairs from old table to new table
        for key_value_res in migrate_from_iterator {
            let (key, value) = key_value_res.unwrap();
            ledger_db.insert_into_cf_raw(migrate_to_handle, &key, &value)?;
        }
        drop(ledger_db);

        tables_to_drop.push(from.to_string());
        Ok(())
    }
}
