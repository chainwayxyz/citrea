use std::sync::{Arc, OnceLock};

use sov_db::ledger_db::migrations::{LedgerMigration, MigrationName, MigrationVersion};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::LEDGER_TABLES;

pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(vec![Box::new(MigrateVerifiedProofsBySlotNumber {})])
}

/// Table name change migration
/// table name "VerifiedProofsBySlotNumber" is now "VerifiedBatchProofsBySlotNumber"
struct MigrateVerifiedProofsBySlotNumber {}

// Name of the schema was changed from VerifiedProofsBySlotNumber to VerifiedBatchProofsBySlotNumber
impl LedgerMigration for MigrateVerifiedProofsBySlotNumber {
    fn identifier(&self) -> (MigrationName, MigrationVersion) {
        ("MigrateVerifiedProofsBySlotNumber".to_owned(), 1)
    }

    fn execute(&self, ledger_db: Arc<LedgerDB>, max_open_files: Option<i32>) -> anyhow::Result<()> {
        let old_table_name = "VerifiedProofsBySlotNumber";
        let new_table_name = "VerifiedBatchProofsBySlotNumber";

        let path = ledger_db.path().to_path_buf();

        // Drop because we need a new one with the VerifiedProofsBySlotNumber table
        drop(ledger_db);

        let cfg = RocksdbConfig::new(&path, max_open_files);

        let mut ledger_db_tables = LEDGER_TABLES.to_vec();
        ledger_db_tables.push("VerifiedProofsBySlotNumber");

        let ledger_db = LedgerDB::with_config(
            &RocksdbConfig::new(&path, max_open_files),
            Some(ledger_db_tables),
        )?;

        let old_table_handle = ledger_db.get_cf_handle("VerifiedProofsBySlotNumber")?;

        let old_table_iterator = ledger_db.get_iterator_for_cf(old_table_handle, None)?;

        let new_table_handle = ledger_db.get_cf_handle("VerifiedBatchProofsBySlotNumber")?;

        // Insert key value pairs from old table to new table
        for key_value_res in old_table_iterator {
            let (key, value) = key_value_res.unwrap();
            ledger_db.insert_into_cf_raw(new_table_handle, &key, &value)?;
        }

        // Drop the old table
        ledger_db.drop_cf(old_table_name)
    }
}
