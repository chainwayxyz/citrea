use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

mod pending_commitments;
mod pending_proofs;

use pending_commitments::PendingCommitmentsL1HeightFieldAdd;
use pending_proofs::PendingProofsL1HeightFieldAdd;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| {
        vec![
            Box::new(PendingCommitmentsL1HeightFieldAdd {}),
            Box::new(PendingProofsL1HeightFieldAdd {}),
        ]
    })
}
