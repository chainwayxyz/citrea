use std::sync::OnceLock;

use anyhow::anyhow;
use sov_schema_db::SchemaBatch;

use super::migrations::{LedgerDBMigrator, LedgerMigration, MigrationName, MigrationVersion};
use super::LedgerDB;
use crate::ledger_db::{SharedLedgerOps, TestLedgerOps};
use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::TestTableOld;

pub fn successful_migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(OldToNewMigration {})])
}

pub fn failed_migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(|| vec![Box::new(FailedOldToNewMigration {})])
}

struct OldToNewMigration {}
impl LedgerMigration for OldToNewMigration {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("OldToNew".to_owned(), 1)
    }

    fn execute(
        &self,
        ledger_db: sov_rollup_interface::RefCount<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let Some(values) = ledger_db.db.get::<TestTableOld>(&())? else {
            return Ok(());
        };
        for (index, value) in values.into_iter().enumerate() {
            ledger_db.put_value(index as u64, (index as u64, value))?;
        }

        // Clear old table
        ledger_db.db.delete::<TestTableOld>(&())?;
        Ok(())
    }
}

struct FailedOldToNewMigration {}
impl LedgerMigration for FailedOldToNewMigration {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("OldToNew".to_owned(), 1)
    }

    fn execute(
        &self,
        _ledger_db: sov_rollup_interface::RefCount<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        Err(anyhow!("Could not fetch data"))
    }
}

#[test]
fn test_successful_migrations() {
    let ledger_db_path = tempfile::tempdir().unwrap();

    // Write some data to the pre-migrations version of the database.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    let mut schema_batch = SchemaBatch::new();
    schema_batch
        .put::<TestTableOld>(&(), &vec![1, 2, 3, 4, 5])
        .unwrap();
    ledger_db.db.write_schemas(schema_batch).unwrap();
    drop(ledger_db);

    // Run migrations
    let ledger_db_migrator = LedgerDBMigrator::new(ledger_db_path.path(), successful_migrations());
    assert!(matches!(ledger_db_migrator.migrate(None), Ok(())));

    // This instance is post-migrations DB.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    // Check for:
    // 1. The new values are there
    assert_eq!(
        ledger_db.get_values().unwrap(),
        vec![
            (0u64, (0u64, 1u64)),
            (1u64, (1u64, 2u64)),
            (2u64, (2u64, 3u64)),
            (3u64, (3u64, 4u64)),
            (4u64, (4u64, 5u64))
        ]
    );
    // 2. DB has been recorded to be executed
    let executed_migrations = ledger_db.get_executed_migrations().unwrap();
    assert_eq!(executed_migrations.len(), 1);

    // 3. Table has been cleared
    let old_values = ledger_db.db.get::<TestTableOld>(&()).unwrap();
    assert_eq!(old_values, None);
}

#[test]
fn test_failed_migrations() {
    let ledger_db_path = tempfile::tempdir().unwrap();

    // Write some data to the pre-migrations version of the database.
    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();

    let mut schema_batch = SchemaBatch::new();
    schema_batch
        .put::<TestTableOld>(&(), &vec![1, 2, 3, 4, 5])
        .unwrap();
    ledger_db.db.write_schemas(schema_batch).unwrap();
    drop(ledger_db);

    // Run migrations
    let ledger_db_migrator = LedgerDBMigrator::new(ledger_db_path.path(), failed_migrations());
    assert!(ledger_db_migrator.migrate(None).is_err());

    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(ledger_db_path.path(), None, None)).unwrap();
    let executed_migrations = ledger_db.get_executed_migrations().unwrap();
    assert_eq!(executed_migrations.len(), 0);
}
