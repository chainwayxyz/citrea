use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

mod pending_commitment;

use pending_commitment::PendingCommitmentL1HeightFieldAdd;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(PendingCommitmentL1HeightFieldAdd {})])
}
