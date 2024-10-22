use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
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
pub struct LedgerDBMigrator<'a> {
    ledger_path: &'a Path,
    migrations: &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>,
}

impl<'a> LedgerDBMigrator<'a> {
    /// Create new instance of migrator
    pub fn new(
        ledger_path: &'a Path,
        migrations: &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            ledger_path,
            migrations,
        }
    }

    /// Run migrations
    pub fn migrate(&self, max_open_files: Option<i32>) -> anyhow::Result<()> {
        if self.migrations.is_empty() {
            return Ok(());
        }

        debug!("Starting LedgerDB migrations...");

        let original_path = &self.ledger_path;

        let ledger_db =
            LedgerDB::with_config(&RocksdbConfig::new(self.ledger_path, max_open_files))?;
        let executed_migrations = ledger_db.get_executed_migrations()?;
        // Drop the lock file
        drop(ledger_db);

        // Copy files over, if temp_db_path falls out of scope, the directory is removed.
        let temp_db_path = tempfile::tempdir()?;
        copy_db_dir_recursive(original_path, temp_db_path.path())?;

        let new_ledger_db = Arc::new(LedgerDB::with_config(&RocksdbConfig::new(
            temp_db_path.path(),
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

        // Mark migrations as executed separately from the previous loop,
        // to make sure all migrations executed successfully.
        for migration in self.migrations.iter() {
            new_ledger_db
                .put_executed_migration(migration.identifier())
                .expect(
                    "Should mark migrations as executed, otherwise, something is seriously wrong",
                );
        }
        // Stop using the original ledger DB path, i.e drop locks
        drop(new_ledger_db);
        // Construct a backup path adjacent to original path
        let last_part = original_path
            .components()
            .last()
            .ok_or(anyhow!("Original path contains invalid construction"))?
            .as_os_str()
            .to_str()
            .ok_or(anyhow!("Could not extract path of ledger path"))?;
        let backup_path = original_path
            .parent()
            .ok_or(anyhow!(
                "Was not able to determine parent path of ledger DB"
            ))?
            .join(format!("{}-backup", last_part));
        // Backup original DB
        copy_db_dir_recursive(original_path, &backup_path)?;
        // Copy new DB into original path
        copy_db_dir_recursive(temp_db_path.path(), original_path)?;

        Ok(())
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
