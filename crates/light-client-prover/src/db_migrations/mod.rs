use std::sync::OnceLock;

use citrea_common::db_migrations::RemoveUnusedTables;
use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::schema::tables::LIGHT_CLIENT_PROVER_LEDGER_TABLES;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| {
        vec![Box::new(RemoveUnusedTables {
            tables: LIGHT_CLIENT_PROVER_LEDGER_TABLES,
        })]
    })
}
