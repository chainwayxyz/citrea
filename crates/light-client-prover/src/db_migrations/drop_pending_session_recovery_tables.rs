use std::sync::Arc;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::LedgerDB;
use tracing::info;

/// Migration to drop pending session recovery tables that were removed from
/// `LIGHT_CLIENT_PROVER_LEDGER_TABLES`.
pub struct DropPendingSessionRecoveryTables;

impl LedgerMigration for DropPendingSessionRecoveryTables {
    fn identifier(&self) -> (String, u64) {
        ("drop_pending_session_recovery_tables".to_string(), 1)
    }

    fn execute(
        &self,
        _ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let tables = ["PendingBonsaiSessionByJobId", "PendingBoundlessSessionByJobId"];

        for table in tables {
            tables_to_drop.push(table.to_string());
            info!("Removing table '{}'", table);
        }

        Ok(())
    }
}
