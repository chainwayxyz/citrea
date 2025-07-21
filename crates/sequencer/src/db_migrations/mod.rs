use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

/// Migration to drop unused fullnode tables from sequencer databases
mod drop_fullnode_tables;

use drop_fullnode_tables::DropFullnodeTables;

/// Returns the list of migrations that need to be executed in the next fork.
pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(DropFullnodeTables)])
}
