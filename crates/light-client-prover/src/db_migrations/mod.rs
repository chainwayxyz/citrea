use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

mod remove_unused_common_tables;

use remove_unused_common_tables::RemoveUnusedTables;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(RemoveUnusedTables {})])
}
