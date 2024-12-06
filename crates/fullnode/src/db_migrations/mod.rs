use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

use crate::db_migrations::verified_proofs::MigrateVerifiedProofsBySlotNumber;

mod verified_proofs;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(MigrateVerifiedProofsBySlotNumber {})])
}
