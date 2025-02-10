use std::sync::OnceLock;

use sov_db::{ledger_db::migrations::LedgerMigration, schema::tables::FULL_NODE_LEDGER_TABLES};

use crate::db_migrations::verified_batch_proof_encoding::FixVerifiedBatchProofsEncoding;
use citrea_common::migration::{
    MigrateBatchAndSlotByNumber, MigrateVerifiedProofsBySlotNumber, RemoveUnusedTables,
};

mod verified_batch_proof_encoding;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| {
        vec![
            Box::new(MigrateVerifiedProofsBySlotNumber),
            Box::new(MigrateBatchAndSlotByNumber),
            Box::new(RemoveUnusedTables {
                tables: FULL_NODE_LEDGER_TABLES,
            }),
            Box::new(FixVerifiedBatchProofsEncoding {}),
        ]
    })
}
