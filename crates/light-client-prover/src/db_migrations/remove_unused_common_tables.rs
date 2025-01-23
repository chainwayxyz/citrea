use std::sync::Arc;

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::tables::{LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES};

/// Table removal migration
/// tables BatchByNumber and SlotByNumber are removed
pub(crate) struct RemoveUnusedTables {}

impl LedgerMigration for RemoveUnusedTables {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("RemoveUnusedTables".to_owned(), 3)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        // Get difference of LEDGER_TABLES and SEQUENCER_LEDGER_TABLES and drop them
        let mut diff = LEDGER_TABLES.to_vec();
        diff.retain(|x| !LIGHT_CLIENT_PROVER_LEDGER_TABLES.contains(x));
        let diff_tables = diff.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        for table in diff_tables {
            // Check if table exists in the database
            if ledger_db.get_cf_handle(&table).is_ok() {
                tables_to_drop.push(table);
            }
        }
        Ok(())
    }
}
