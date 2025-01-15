use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use serde::Serialize;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::mmr_db::MmrDB;
use sov_prover_storage_manager::SnapshotManager;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};

use super::utils::{restore_from_backup, validate_backup};

const REQUIRED_BACKUP_DIRS: [&str; 3] = ["ledger", "state", "native-db"];
const OPTIONAL_BACKUP_DIRS: [&str; 1] = ["mmr"];

/// Manager for creating and restoring database backups while maintaining consistency
/// with L1/L2 block processing.
pub struct BackupManager {
    /// LedgerDB
    ledger_db: LedgerDB,
    /// StateDB
    state_db: Arc<RwLock<SnapshotManager>>,
    /// NativeDB
    native_db: Arc<RwLock<SnapshotManager>>,
    /// Optional MmrDB
    mmr_db: Option<MmrDB>,
    /// Lock to hold during l1 block processing
    l1_processing_lock: Mutex<()>,
    /// Lock to hold during l2 block processing
    l2_processing_lock: Mutex<()>,
}

/// Information about a created backup
#[derive(Debug, Clone, Serialize)]
pub struct BackupInfo {
    /// L2 block height when backup was created
    pub block_height: u64,
    /// Full path to the backup directory
    pub backup_path: PathBuf,
    /// Unix timestamp when backup was created
    pub created_at: u64,
}

impl BackupManager {
    /// Creates a new BackupManager instance with the provided databases.
    ///
    /// # Arguments
    /// * `ledger_db` - The LedgerDB database
    /// * `state_db` - The SnapshotManager holding the underlying state_db database
    /// * `native_db` - The SnapshotManager holding the underlying native_db database
    /// * `mmr_db` - Optional MMR database used by light client prover
    pub fn new(
        ledger_db: LedgerDB,
        state_db: Arc<RwLock<SnapshotManager>>,
        native_db: Arc<RwLock<SnapshotManager>>,
        mmr_db: Option<MmrDB>,
    ) -> Self {
        Self {
            ledger_db,
            state_db,
            native_db,
            mmr_db,
            l1_processing_lock: Mutex::new(()),
            l2_processing_lock: Mutex::new(()),
        }
    }

    /// Acquires a lock for L1 block processing.
    /// Should be held while any L1 block operation is taken
    pub async fn start_l1_processing(&self) -> MutexGuard<'_, ()> {
        self.l1_processing_lock.lock().await
    }

    /// Acquires a lock for L2 block processing.
    /// Should be held while any L2 block operation is taken
    pub async fn start_l2_processing(&self) -> MutexGuard<'_, ()> {
        self.l2_processing_lock.lock().await
    }

    /// Creates a backup of all the databases at `REQUIRED_BACKUP_DIRS` and `OPTIONAL_BACKUP_DIRS` at the specified path.
    ///
    /// Acquires both L1 and L2 processing locks to ensure consistency and make sure no writes are happening while backing up.
    /// The backup will be created in a subdirectory named `backup_<l2_height>_<timestamp>`.
    ///
    /// # Arguments
    /// * `path` - Base directory where the backup will be created
    ///
    /// # Returns
    /// Information about the created backup including block height, path and timestamp
    pub(super) async fn create_backup(&self, path: impl AsRef<Path>) -> anyhow::Result<BackupInfo> {
        let _l1_lock = self.l1_processing_lock.lock().await;
        let _l2_lock = self.l2_processing_lock.lock().await;

        let start_time = Instant::now();
        info!("Starting database backup process...");

        let l2_height = self
            .ledger_db
            .get_head_soft_confirmation_height()?
            .unwrap_or_default();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let backup_path = path
            .as_ref()
            .join(format!("backup_{}_{}", l2_height, timestamp));
        info!("Creating backup at path {}", backup_path.display());

        let mut handles = Vec::new();

        let ledger_db = self.ledger_db.clone();
        let ledger_path = backup_path.join("ledger");
        handles.push(tokio::spawn(async move {
            ledger_db.db_ref().create_backup(&ledger_path)?;
            Ok::<(), anyhow::Error>(())
        }));

        let state_db = self.state_db.clone();
        let state_path = backup_path.join("state");
        handles.push(tokio::spawn(async move {
            state_db
                .read()
                .unwrap()
                .db_ref()
                .create_backup(&state_path)?;
            Ok::<(), anyhow::Error>(())
        }));

        let native_db = self.native_db.clone();
        let native_path = backup_path.join("native-db");
        handles.push(tokio::spawn(async move {
            native_db
                .read()
                .unwrap()
                .db_ref()
                .create_backup(&native_path)?;
            Ok::<(), anyhow::Error>(())
        }));

        if let Some(mmr_db) = self.mmr_db.clone() {
            let mmr_path = backup_path.join("mmr");
            handles.push(tokio::spawn(async move {
                mmr_db.db_ref().create_backup(&mmr_path)?;
                Ok::<(), anyhow::Error>(())
            }));
        }

        // Wait for all dbs to starting backing up under lock before releasing
        drop(_l1_lock);
        drop(_l2_lock);

        for handle in handles {
            handle.await.unwrap()?;
        }

        if let Err(e) = Self::validate_backup(&backup_path) {
            warn!("Error validating backup: {}", e);
            bail!("Error creating valid backup: {e}");
        }

        let info = BackupInfo {
            block_height: l2_height,
            backup_path,
            created_at: timestamp,
        };

        info!(
            "Backup process completed successfully in {:.2}s. Backup info: {:?}",
            start_time.elapsed().as_secs_f32(),
            info
        );

        Ok(info)
    }

    /// Atomically restore databases from a backup at backup_path.
    ///
    /// # Safety Guarantees
    /// - Validates backup integrity before starting restoration
    /// - Uses temporary directory for restoration to prevent partial/corrupted restores
    /// - Preserves existing database by renaming it with .bak extension if present
    /// - Performs atomic rename operations for final restoration
    ///
    /// # Process
    /// 1. Validates backup integrity via validate_backup()
    /// 2. Creates a temporary directory with .tmp extension
    /// 3. Restores all required databases to temp directory
    /// 4. Restores any optional databases if present in backup
    /// 5. If original database exists, keeps a raw fs backup and rename it to .bak
    /// 6. Atomically renames temp directory to target location
    ///
    /// # Arguments
    /// * `db_path` - Target path where databases should be restored
    /// * `backup_path` - Source backup path containing database backups
    ///
    /// # Errors
    /// Returns error if:
    /// - Backup validation fails
    /// - Any required database fails to restore
    /// - File system operations (create/rename) fail
    /// ```
    pub fn restore_dbs_from_backup(
        db_path: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        // Validate backup before trying to restore
        Self::validate_backup(&backup_path)?;
        let start_time = Instant::now();
        info!("Starting database restore process...");

        let original_path = db_path.as_ref();
        let backup_path = backup_path.as_ref();
        info!(
            "Restoring from backup at path {} to {}",
            backup_path.display(),
            original_path.display()
        );
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let tmp_path = original_path.with_extension(format!("tmp-{timestamp}"));
        info!("Using {} as temporary restore path", tmp_path.display());

        let inner_restore_from_backup = |dir: &str| {
            let dir_start = Instant::now();
            info!("Restoring {dir} database");
            let backup_path = backup_path.join(dir);
            let path = tmp_path.join(dir);
            let res = restore_from_backup(path, backup_path);
            info!(
                "{dir} database restore completed in {:.2}s",
                dir_start.elapsed().as_secs_f32()
            );
            res
        };

        for dir in REQUIRED_BACKUP_DIRS {
            inner_restore_from_backup(dir)?;
        }

        for dir in OPTIONAL_BACKUP_DIRS {
            let backup_path = backup_path.join(dir);
            if backup_path.exists() {
                inner_restore_from_backup(dir)?;
            }
        }

        if original_path.exists() {
            info!(
                "Database path already exists: {}, backing up to {}.bak-{timestamp}",
                original_path.display(),
                original_path.display()
            );

            std::fs::rename(
                original_path,
                original_path.with_extension(format!("bak-{timestamp}")),
            )
            .context("Failed to backup existing database")?;
        }
        std::fs::rename(&tmp_path, original_path)?;

        info!(
            "Successfully restored databases from backup at {} to {} in {:.2}s",
            backup_path.display(),
            original_path.display(),
            start_time.elapsed().as_secs_f32(),
        );
        Ok(())
    }

    /// Validates the integrity of a backup directory.
    ///
    /// Checks that:
    /// - All required directories exist and are not empty
    /// - Each database backup can be validated
    /// - Optional directories are validated if present
    ///
    /// # Arguments
    /// * `backup_path` - Path to the backup directory to validate
    pub(super) fn validate_backup(backup_path: impl AsRef<Path>) -> anyhow::Result<()> {
        let backup_path = backup_path.as_ref();

        if !backup_path.exists() {
            bail!("Backup directory does not exist: {:?}", backup_path);
        }

        let innner_validate_backup = |dir: &str| {
            let path = backup_path.join(dir);
            if !path.exists() {
                bail!("Missing required directory '{}' in backup", dir);
            }

            if path.read_dir()?.next().is_none() {
                bail!("Directory '{}' is empty ", dir);
            }

            validate_backup(&path)
        };

        for dir in REQUIRED_BACKUP_DIRS {
            innner_validate_backup(dir)?;
        }

        for dir in OPTIONAL_BACKUP_DIRS {
            let dir_path = backup_path.join(dir);
            if dir_path.exists() {
                innner_validate_backup(dir)?;
            }
        }

        Ok(())
    }
}
