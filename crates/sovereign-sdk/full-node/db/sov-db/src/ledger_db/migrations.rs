use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{debug, error};

use super::LedgerDB;
use crate::ledger_db::SharedLedgerOps;
use crate::rocks_db_config::RocksdbConfig;

/// Alias for migration name type
pub type MigrationName = String;
/// Alias for migration version type
pub type MigrationVersion = u64;

/// A trait that should be implemented by migrations.
pub trait LedgerMigration {
    /// Provide an identifier for this migration
    fn identifier(&self) -> (MigrationName, MigrationVersion);
    /// Execute current migration on ledger DB
    fn execute(&self, ledger_db: Arc<LedgerDB>) -> anyhow::Result<()>;
}

/// Handler for ledger DB migrations.
///
/// This implements migrations in an atomic fashion.
/// Meaning that, if any migration would fail, the whole process
/// is rolled back to the previous version, rendering the changes
/// made by any run migration useless.
pub struct LedgerDBMigrator {
    ledger_path: PathBuf,
    migrations: &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>,
}

impl LedgerDBMigrator {
    /// Create new instance of migrator
    pub fn new(
        ledger_path: PathBuf,
        migrations: &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            ledger_path,
            migrations,
        }
    }

    /// Run migrations
    pub fn migrate(&self, max_open_files: Option<i32>) -> anyhow::Result<()> {
        debug!("Starting LedgerDB migrations...");
        let original_path = &self.ledger_path;

        let ledger_db =
            LedgerDB::with_config(&RocksdbConfig::new(&self.ledger_path, max_open_files))?;

        let executed_migrations = ledger_db.get_executed_migrations()?;

        let temp_db_path = self.make_temp_db_copy(original_path)?;
        let new_ledger_db = Arc::new(LedgerDB::with_config(&RocksdbConfig::new(
            &temp_db_path,
            max_open_files,
        ))?);

        for migration in self.migrations {
            if !executed_migrations.contains(&migration.identifier()) {
                debug!("Running migration: {}", migration.identifier().0);
                if let Err(e) = migration.execute(new_ledger_db.clone()) {
                    error!(
                        "Error executing migration {}: {:?}",
                        migration.identifier().0,
                        e
                    );

                    // Error happend on the temporary DB, therefore,
                    // nothing needs to be done to keep operating on existing
                    // ledger instance.
                    return Ok(());
                }
            } else {
                debug!(
                    "Skip previously executed migration: {}",
                    migration.identifier().0
                );
            }
        }

        // Stop using the original ledger DB path, i.e drop locks
        drop(new_ledger_db);
        // Backup original DB
        copy_db_dir_recursive(&original_path, &original_path.join("backup"))?;
        // Copy new DB into original path
        copy_db_dir_recursive(&temp_db_path, original_path)?;
        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(original_path, max_open_files))?;

        for migration in self.migrations.iter() {
            ledger_db
                .put_executed_migration(migration.identifier())
                .expect(
                    "Should mark migrations as executed, otherwise, something is seriously wrong",
                );
        }

        Ok(())
    }

    fn make_temp_db_copy(&self, src: &Path) -> anyhow::Result<PathBuf> {
        let dst = tempfile::tempdir()?;
        copy_db_dir_recursive(src, &dst.path())?;
        Ok(dst.path().to_path_buf())
    }
}

/// Copy DB files from src to dst.
pub fn copy_db_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let target_path = dst.join(entry.file_name());

        if entry_path.is_dir() {
            copy_db_dir_recursive(&entry_path, &target_path)?;
        } else {
            fs::copy(&entry_path, &target_path)?;
        }
    }
    Ok(())
}
