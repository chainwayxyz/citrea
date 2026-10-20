use std::sync::Arc;

use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::LedgerDB;
use tracing::info;

/// Migration to drop the persistent mempool table. The mempool is kept in memory only, so
/// transactions stored by previous versions must not be restored.
pub struct DropMempoolTxs;

impl LedgerMigration for DropMempoolTxs {
    fn identifier(&self) -> (String, u64) {
        ("drop_mempool_txs".to_string(), 1)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let table_name = "MempoolTxs";
        if ledger_db
            .db_handle()
            .list_column_families()
            .iter()
            .any(|name| name == table_name)
        {
            tables_to_drop.push(table_name.to_string());
            info!("Removing table '{table_name}'");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::SEQUENCER_LEDGER_TABLES;

    use super::*;

    /// Runs the real migration twice against an existing ledger, with or without the old table.
    fn migrate_existing_ledger(has_legacy_table: bool) {
        static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync>>> = OnceLock::new();
        let migrations: Migrations = MIGRATIONS.get_or_init(|| vec![Box::new(DropMempoolTxs)]);
        let directory = tempfile::tempdir().unwrap();
        let tables = SEQUENCER_LEDGER_TABLES
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>();
        let mut initial_tables = tables.clone();
        if has_legacy_table {
            initial_tables.push("MempoolTxs".to_string());
        }
        let ledger = LedgerDB::with_config(&RocksdbConfig::new(
            directory.path(),
            None,
            Some(initial_tables),
        ))
        .unwrap();
        drop(ledger);
        let migrator = LedgerDBMigrator::new(directory.path(), migrations);
        migrator.migrate(None, tables.clone()).unwrap();
        migrator.migrate(None, tables).unwrap();
        assert!(
            !sov_db::ledger_db::migrations::utils::list_column_families(directory.path())
                .iter()
                .any(|name| name == "MempoolTxs")
        );
    }

    #[test]
    fn drops_legacy_mempool_table() {
        migrate_existing_ledger(true);
    }

    #[test]
    fn tolerates_absent_mempool_table() {
        migrate_existing_ledger(false);
    }
}
