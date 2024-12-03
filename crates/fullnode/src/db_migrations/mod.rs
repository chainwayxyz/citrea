use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::schema::tables::LEDGER_TABLES;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(Vec::new)
}

struct MigrateVerifiedProofsBySlotNumber {}

// Name of the schema was changed from VerifiedProofsBySlotNumber to VerifiedBatchProofsBySlotNumber
impl LedgerMigration for MigrateVerifiedProofsBySlotNumber {
    fn identifier(
        &self,
    ) -> (
        sov_db::ledger_db::migrations::MigrationName,
        sov_db::ledger_db::migrations::MigrationVersion,
    ) {
        ("MigrateVerifiedProofsBySlotNumber".to_owned(), 1)
    }

    fn execute(
        &self,
        ledger_db: std::sync::Arc<sov_db::ledger_db::LedgerDB>,
    ) -> anyhow::Result<()> {
        todo!()
    }
}
