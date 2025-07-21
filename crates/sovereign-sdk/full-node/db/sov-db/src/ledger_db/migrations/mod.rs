use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use sov_rollup_interface::RefCount;
use tracing::{debug, error, info};

use super::migrations::utils::{drop_column_families, list_column_families};
use super::LedgerDB;
use crate::ledger_db::SharedLedgerOps;
use crate::rocks_db_config::RocksdbConfig;

/// Utilities for ledger db migrations
pub mod utils;

/// Alias for migration name type
pub type MigrationName = String;
/// Alias for migration version type
pub type MigrationVersion = u64;
/// Alias for migrations list
pub type Migrations = &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>;

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
    migrations: Migrations,
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
    pub fn migrate(
        &self,
        max_open_files: Option<i32>,
        node_column_families: Vec<String>,
    ) -> anyhow::Result<()> {
        if self.migrations.is_empty() {
            return Ok(());
        }

        let dbs_path = &self.ledger_path;

        if !dbs_path.join(LedgerDB::DB_PATH_SUFFIX).exists() {
            // If this is the first time the ledger db is being created, then we don't need to run migrations
            // all migrations up to this point are considered successful
            let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
                self.ledger_path,
                max_open_files,
                Some(node_column_families),
            ))?;

            for migration in self.migrations.iter() {
                ledger_db
                    .put_executed_migration(migration.identifier())
                    .expect(
                    "Should mark migrations as executed, otherwise, something is seriously wrong",
                );
            }

            info!("Creating ledger DB for the first time, no migrations to run.");

            return Ok(());
        }

        info!("Checking for pending LedgerDB migrations...");

        let column_families_in_db = list_column_families(self.ledger_path);

        let all_column_families =
            merge_column_families(column_families_in_db, node_column_families);

        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            self.ledger_path,
            max_open_files,
            Some(all_column_families.clone()),
        ))?;

        // Return an empty vector for executed migrations in case of an error since the iteration fails
        // because of the absence of the table.
        let executed_migrations = ledger_db.get_executed_migrations().unwrap_or(vec![]);
        let unexecuted_migrations: Vec<_> = self
            .migrations
            .iter()
            .filter(|migration| !executed_migrations.contains(&migration.identifier()))
            .collect();

        // Do not invoke backup the database and prepare for migration
        // if there are no migrations that were not previously executed.
        if unexecuted_migrations.is_empty() {
            info!("No pending ledger migrations found, skipping.");
            return Ok(());
        }

        info!("Pending migrations exist. Applying...");

        let mut tables_to_drop = vec![];

        info!("Executing pending migrations.");
        let ledger_db = RefCount::new(ledger_db);
        for migration in unexecuted_migrations {
            debug!("Running migration: {}", migration.identifier().0);
            if let Err(e) = migration.execute(ledger_db.clone(), &mut tables_to_drop) {
                error!(
                    "Error executing migration {}\n: {:?}",
                    migration.identifier().0,
                    e
                );

                // Error happened on the temporary DB, therefore,
                // fail the node.
                return Err(e);
            }
        }

        // Mark migrations as executed separately from the previous loop,
        // to make sure all migrations executed successfully.
        for migration in self.migrations.iter() {
            ledger_db
                .put_executed_migration(migration.identifier())
                .expect(
                    "Should mark migrations as executed, otherwise, something is seriously wrong",
                );
        }

        // Drop the lock file
        drop(ledger_db);

        // Now that the lock is gone drop the tables that were migrated

        drop_column_families(
            &RocksdbConfig::new(
                self.ledger_path,
                max_open_files,
                Some(all_column_families.clone()),
            ),
            tables_to_drop,
        )?;

        info!("Migrations executed successfully.");

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

fn merge_column_families(
    column_families_in_db: Vec<String>,
    node_column_families: Vec<String>,
) -> Vec<String> {
    let column_families: HashSet<String> = node_column_families
        .iter()
        .map(|table_name| table_name.to_string())
        .chain(column_families_in_db)
        .collect();
    column_families.into_iter().collect()
}
