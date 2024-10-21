use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

#[allow(dead_code)]
pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![])
}
