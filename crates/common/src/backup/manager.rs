use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use rocksdb::backup::BackupEngineInfo;
use serde::{Deserialize, Serialize};
use sov_db::traits::Backup;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};

use super::utils::{get_backup_engine, restore_from_backup, validate_backup};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Required backup directories
    pub required_dirs: Vec<String>,
    /// Optional backup directories
    pub optional_dirs: Vec<String>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            required_dirs: vec![
                "ledger".to_string(),
                "state".to_string(),
                "native-db".to_string(),
            ],
            optional_dirs: vec!["mmr".to_string()],
        }
    }
}

/// Manager for creating and restoring database backups while maintaining consistency
/// with L1/L2 block processing.
pub struct BackupManager {
    /// Node kind
    node_kind: &'static str,
    /// Optional base path used for backups. Can be overridden via RPC
    base_path: Option<PathBuf>,
    /// Map of path to backupable database
    databases: HashMap<String, Arc<dyn Backup>>,
    /// Lock to hold during l1 block processing
    l1_processing_lock: Mutex<()>,
    /// Lock to hold during l2 block processing
    l2_processing_lock: Mutex<()>,
    /// Backup configuration. Holds required and optional dirs.
    pub config: BackupConfig,
}

/// Information about a created backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBackupInfo {
    /// Node kind
    pub node_kind: String,
    /// L2 block height when backup was created
    pub block_height: u64,
    /// Full path to the backup directory
    pub backup_path: PathBuf,
    /// Unix timestamp when backup was created
    pub created_at: u64,
    /// Backup id
    pub backup_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BackupMetadata {
    node_kind: String,
    backups: HashMap<u32, u64>, // backup_id -> block_height
}

impl BackupManager {
    /// Creates a new BackupManager instance with the provided databases.
    ///
    /// # Arguments
    /// * `node_kind` - The citrea node kind associated with the BackupManager
    /// * `base_path` - Optional base_path which will be used for creating backups.
    /// * `config` - Optional config to override required/optional directories
    pub fn new(
        // Todo Wait on https://github.com/chainwayxyz/citrea/pull/1714 and RollupClient enum
        node_kind: &'static str,
        base_path: Option<PathBuf>,
        config: Option<BackupConfig>,
    ) -> Self {
        Self {
            node_kind,
            base_path,
            databases: HashMap::new(),
            l1_processing_lock: Mutex::new(()),
            l2_processing_lock: Mutex::new(()),
            config: config.unwrap_or_default(),
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

    /// Add a database to be backed up
    pub fn add_database(&mut self, path: &str, db: impl Backup + 'static) {
        self.databases.insert(path.to_string(), Arc::new(db));
    }

    /// Creates a backup of all the databases at `REQUIRED_BACKUP_DIRS` and `OPTIONAL_BACKUP_DIRS` at the specified path.
    ///
    /// Acquires both L1 and L2 processing locks to ensure consistency between dbs
    ///
    /// # Arguments
    /// * `path` - Base directory where the backup will be created
    ///
    /// # Returns
    /// Information about the created backup including block height, path and timestamp
    pub(super) async fn create_backup(
        &self,
        path: impl AsRef<Path>,
        l2_height: u64,
    ) -> anyhow::Result<CreateBackupInfo> {
        let _l1_lock = self.l1_processing_lock.lock().await;
        let _l2_lock = self.l2_processing_lock.lock().await;

        let start_time = Instant::now();
        info!("Starting database backup process...");

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let backup_path = path.as_ref();
        info!(
            "Creating {} backup at path {}",
            self.node_kind,
            backup_path.display()
        );

        let mut handles = Vec::new();

        for dir in &self.config.required_dirs {
            let path = backup_path.join(dir);
            let db = self
                .databases
                .get(dir)
                .context("Missing required db")?
                .clone();
            handles.push(tokio::task::spawn_blocking(move || db.backup(&path)));
        }

        // Wait for all dbs to starting backing up under lock before releasing
        drop(_l1_lock);
        drop(_l2_lock);

        for handle in handles {
            handle.await??;
        }

        if let Err(e) = self.validate_backup(backup_path) {
            warn!("Error validating backup: {e}");
            bail!("Error creating valid backup: {e}");
        }

        let backup_info = self.get_backup_info(backup_path)?;
        let backup_id = backup_info.get("ledger").unwrap().last().unwrap().backup_id;

        let info = CreateBackupInfo {
            node_kind: self.node_kind.to_string(),
            block_height: l2_height,
            backup_path: backup_path.to_path_buf(),
            created_at: timestamp,
            backup_id,
        };

        info!(
            "Backup process completed successfully in {:.2}s. Backup info: {:?}",
            start_time.elapsed().as_secs_f32(),
            info
        );

        self.set_metadata(&backup_path, &info).await?;

        Ok(info)
    }

    async fn set_metadata(
        &self,
        backup_path: impl AsRef<Path>,
        info: &CreateBackupInfo,
    ) -> anyhow::Result<()> {
        let metadata_path = backup_path.as_ref().join(".metadata");
        let mut metadata = if metadata_path.exists() {
            let content = tokio::fs::read_to_string(&metadata_path).await?;
            serde_json::from_str(&content)?
        } else {
            BackupMetadata {
                node_kind: self.node_kind.to_string(),
                backups: HashMap::new(),
            }
        };
        metadata.backups.insert(info.backup_id, info.block_height);
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        tokio::fs::write(metadata_path, metadata_json).await?;
        Ok(())
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
        &self,
        db_path: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        // Validate backup before trying to restore
        self.validate_backup(&backup_path)?;

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

        for dir in &self.config.required_dirs {
            inner_restore_from_backup(dir)?;
        }

        for dir in &self.config.optional_dirs {
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
    pub(super) fn validate_backup(&self, backup_path: impl AsRef<Path>) -> anyhow::Result<()> {
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

        for dir in &self.config.required_dirs {
            innner_validate_backup(dir)?;
        }

        for dir in &self.config.optional_dirs {
            let dir_path = backup_path.join(dir);
            if dir_path.exists() {
                innner_validate_backup(dir)?;
            }
        }

        Ok(())
    }

    pub(super) fn get_backup_info(
        &self,
        backup_path: impl AsRef<Path>,
    ) -> anyhow::Result<HashMap<String, Vec<BackupEngineInfo>>> {
        let backup_path = backup_path.as_ref();

        if !backup_path.exists() {
            bail!("Backup directory does not exist: {:?}", backup_path);
        }

        let mut map = HashMap::new();

        for dir in &self.config.required_dirs {
            let engine = get_backup_engine(backup_path.join(dir))?;
            map.insert(dir.to_string(), engine.get_backup_info());
        }

        for dir in &self.config.optional_dirs {
            let dir_path = backup_path.join(dir);
            if dir_path.exists() {
                let engine = get_backup_engine(dir_path)?;
                map.insert(dir.to_string(), engine.get_backup_info());
            }
        }

        Ok(map)
    }
}
