use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

mod pruned_height;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(pruned_height::MigratePrunedL2Height {})])
}
