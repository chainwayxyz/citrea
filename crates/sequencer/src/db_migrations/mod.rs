use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

/// Returns the list of migrations that need to be executed in the next fork.
pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(std::vec::Vec::new)
}
