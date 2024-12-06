use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
use tracing::{debug, error};

use super::migrations::utils::{drop_column_family, list_column_families};
use super::LedgerDB;
use crate::ledger_db::{SharedLedgerOps, LEDGER_DB_PATH_SUFFIX};
use crate::rocks_db_config::RocksdbConfig;
use crate::schema::tables::LEDGER_TABLES;

/// Utilities for ledger db migrations
pub mod utils;

/// Alias for migration name type
pub type MigrationName = String;
/// Alias for migration version type
pub type MigrationVersion = u64;

/// A trait that should be implemented by migrations.
pub trait LedgerMigration {
    /// Provide an identifier for this migration
    fn identifier(&self) -> (MigrationName, MigrationVersion);
    /// Execute current migration on ledger DB
    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()>;
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

        let dbs_path = &self.ledger_path;

        if !dbs_path.join(LEDGER_DB_PATH_SUFFIX).exists() {
            // If this is the first time the ledger db is being created, then we don't need to run migrations
            // all migrations up to this point are considered successful
            let ledger_db =
                LedgerDB::with_config(&RocksdbConfig::new(self.ledger_path, max_open_files, None))?;

            for migration in self.migrations.iter() {
                ledger_db
                    .put_executed_migration(migration.identifier())
                    .expect(
                    "Should mark migrations as executed, otherwise, something is seriously wrong",
                );
            }
            return Ok(());
        }

        let column_families_in_db = list_column_families(self.ledger_path);

        let all_column_families = merge_column_families(column_families_in_db);

        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            self.ledger_path,
            max_open_files,
            Some(all_column_families.clone()),
        ))?;

        // Return an empty vector for executed migrations in case of an error since the iteration fails
        // because of the absence of the table.
        let executed_migrations = ledger_db.get_executed_migrations().unwrap_or(vec![]);

        // Drop the lock file
        drop(ledger_db);

        // Copy files over, if temp_db_path falls out of scope, the directory is removed.
        let temp_db_path = tempfile::tempdir()?;
        copy_db_dir_recursive(dbs_path, temp_db_path.path())?;

        let new_ledger_db = Arc::new(LedgerDB::with_config(&RocksdbConfig::new(
            temp_db_path.path(),
            max_open_files,
            Some(all_column_families.clone()),
        ))?);

        let mut tables_to_drop = vec![];

        for migration in self.migrations {
            if !executed_migrations.contains(&migration.identifier()) {
                debug!("Running migration: {}", migration.identifier().0);
                if let Err(e) = migration.execute(new_ledger_db.clone(), &mut tables_to_drop) {
                    error!(
                        "Error executing migration {}\n: {:?}",
                        migration.identifier().0,
                        e
                    );

                    // Error happened on the temporary DB, therefore,
                    // fail the node.
                    return Err(e);
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

        // Now that the lock is gone drop the tables that were migrated
        for table in tables_to_drop {
            drop_column_family(
                &RocksdbConfig::new(
                    temp_db_path.path(),
                    max_open_files,
                    Some(all_column_families.clone()),
                ),
                &table,
            )?;
        }

        // Construct a backup path adjacent to original path
        let ledger_path = dbs_path.join(LEDGER_DB_PATH_SUFFIX);
        let temp_ledger_path = temp_db_path.path().join(LEDGER_DB_PATH_SUFFIX);
        let last_part = ledger_path
            .components()
            .last()
            .ok_or(anyhow!("Original path contains invalid construction"))?
            .as_os_str()
            .to_str()
            .ok_or(anyhow!("Could not extract path of ledger path"))?;

        let backup_path = ledger_path
            .parent()
            .ok_or(anyhow!(
                "Was not able to determine parent path of ledger DB"
            ))?
            .join(format!("{}-backup", last_part));

        // Initially clear the backup path
        clear_db_dir(&backup_path)?;

        // Backup original DB
        copy_db_dir_recursive(&ledger_path, &backup_path)?;

        // Initially clear the original path
        clear_db_dir(&ledger_path)?;
        assert!(!ledger_path.exists(), "Failed to clear original path");

        // Copy new DB into original path
        copy_db_dir_recursive(&temp_ledger_path, &ledger_path)?;

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

fn merge_column_families(column_families_in_db: Vec<String>) -> Vec<String> {
    let column_families: HashSet<String> = LEDGER_TABLES
        .iter()
        .map(|&table_name| table_name.to_string())
        .chain(column_families_in_db)
        .collect();
    column_families.into_iter().collect()
}

/// Completely clears the given path
pub fn clear_db_dir(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}
