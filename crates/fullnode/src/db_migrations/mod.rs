use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

use crate::db_migrations::batch_and_slot_by_number::MigrateBatchAndSlotByNumber;
use crate::db_migrations::verified_proofs::MigrateVerifiedProofsBySlotNumber;

mod batch_and_slot_by_number;
mod verified_proofs;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| {
        vec![
            Box::new(MigrateVerifiedProofsBySlotNumber {}),
            Box::new(MigrateBatchAndSlotByNumber {}),
        ]
    })
}
