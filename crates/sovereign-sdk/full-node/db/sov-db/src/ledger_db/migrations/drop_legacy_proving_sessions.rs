use std::sync::Arc;

use super::LedgerMigration;
use crate::ledger_db::LedgerDB;

const LEGACY_SESSION_TABLES: [&str; 4] = [
    "PendingBonsaiSessionByJobId",
    "PendingBoundlessSessionByJobId",
    "ProvingSessionInfoByJobId",
    "ProvingSessionInfoBySlotNumber",
];

/// Discard RISC0 session history and recovery state without decoding legacy values.
/// The current session tables are recreated empty when the prover opens its ledger.
pub struct DropLegacyProvingSessions;

impl LedgerMigration for DropLegacyProvingSessions {
    fn identifier(&self) -> (String, u64) {
        ("drop_legacy_proving_sessions".to_string(), 1)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let tables = ledger_db.db_handle().list_column_families();
        for name in LEGACY_SESSION_TABLES {
            if tables.iter().any(|table| table == name) {
                tables_to_drop.push(name.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::ledger_db::migrations::utils::list_column_families;
    use crate::ledger_db::migrations::{LedgerDBMigrator, Migrations};
    use crate::ledger_db::SharedLedgerOps;
    use crate::rocks_db_config::RocksdbConfig;
    use crate::schema::tables::BATCH_PROVER_LEDGER_TABLES;

    fn migrations() -> Migrations {
        static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync>>> = OnceLock::new();
        MIGRATIONS.get_or_init(|| vec![Box::new(DropLegacyProvingSessions)])
    }

    #[test]
    fn drops_legacy_tables_without_decoding_them() {
        let directory = tempfile::tempdir().unwrap();
        let tables = BATCH_PROVER_LEDGER_TABLES
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>();
        let mut old_tables = tables.clone();
        for name in LEGACY_SESSION_TABLES {
            if !old_tables.iter().any(|table| table == name) {
                old_tables.push(name.to_string());
            }
        }
        let ledger = LedgerDB::with_config(&RocksdbConfig::new(
            directory.path(),
            None,
            Some(old_tables),
        ))
        .unwrap();
        for name in LEGACY_SESSION_TABLES {
            // Invalid legacy bytes ensure migration never tries to decode a session.
            ledger
                .insert_into_cf_raw(ledger.get_cf_handle(name).unwrap(), b"old", &[1, 2])
                .unwrap();
        }
        ledger
            .put_executed_migration(("drop_pending_session_recovery_tables".into(), 1))
            .unwrap();
        drop(ledger);

        LedgerDBMigrator::new(directory.path(), migrations())
            .migrate(None, tables)
            .unwrap();
        let remaining = list_column_families(directory.path());
        assert!(LEGACY_SESSION_TABLES
            .iter()
            .all(|name| !remaining.iter().any(|table| table == name)));
    }
}
