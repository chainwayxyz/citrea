use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure, Context};
use rocksdb::backup::BackupEngineInfo;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps, LEDGER_DB_PATH_SUFFIX};
use sov_db::mmr_db::MmrDB;
use sov_db::native_db::NativeDB;
use sov_db::state_db::StateDB;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{info, warn};

use super::utils::{get_backup_engine, restore_from_backup, validate_backup};

/// Configuration for database backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// List of database directories that should be included in backups
    pub backup_dirs: Vec<String>,
}

impl BackupConfig {
    fn new(node_kind: &str) -> Self {
        let mut backup_dirs = vec![
            LEDGER_DB_PATH_SUFFIX.to_string(),
            StateDB::<()>::DB_PATH_SUFFIX.to_string(),
            NativeDB::<()>::DB_PATH_SUFFIX.to_string(),
        ];

        if node_kind == "light-client-prover" {
            backup_dirs.push(MmrDB::DB_PATH_SUFFIX.to_string());
        }

        Self { backup_dirs }
    }
}

/// Manager for creating and restoring database backups while maintaining consistency
/// with L1/L2 block processing.
pub struct BackupManager {
    /// Node kind
    node_kind: String,
    /// Optional base path used for backups. Can be overridden via RPC
    base_path: Option<PathBuf>,
    /// Map of path to backupable database
    databases: RwLock<HashMap<String, Arc<sov_schema_db::DB>>>,
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
    version: u32,
    node_kind: String,
    backups: HashMap<u32, u64>, // backup_id -> block_height
}

impl BackupManager {
    /// Creates a new BackupManager instance.
    ///
    /// # Arguments
    /// * `node_kind` - The citrea node kind associated with the BackupManager
    /// * `base_path` - Optional base_path which will be used for creating backups.
    /// * `config` - Optional config to override required/optional directories
    pub fn new(
        // Todo Wait on https://github.com/chainwayxyz/citrea/pull/1714 and RollupClient enum
        node_kind: String,
        base_path: Option<PathBuf>,
        config: Option<BackupConfig>,
    ) -> Self {
        let config = config.unwrap_or_else(|| BackupConfig::new(&node_kind));

        Self {
            node_kind,
            base_path,
            databases: RwLock::new(HashMap::new()),
            l1_processing_lock: Mutex::new(()),
            l2_processing_lock: Mutex::new(()),
            config,
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

    /// Register a database with the backup manager.
    ///
    /// # Arguments
    /// * `path` - Identifier/path for the database (e.g. "ledger", "state", "native-db")
    /// * `db` - Reference to the database instance
    ///
    /// # Returns
    /// * `Ok(())` if registration succeeds
    /// * `Err` if the path is not in the configured backup directories
    ///
    /// # Errors
    /// Returns error if the provided path is not present in backup_dirs configuration
    pub fn register_database(
        &self,
        path: String,
        db: Arc<sov_schema_db::DB>,
    ) -> anyhow::Result<()> {
        ensure!(
            self.config.backup_dirs.contains(&path),
            "Unexpect database identifier"
        );
        self.databases.write().unwrap().insert(path, db);
        Ok(())
    }

    /// Creates a backup of all the databases held in config at the specified path.
    ///
    /// Acquires both L1 and L2 processing locks to ensure consistency between dbs
    ///
    /// # Arguments
    /// * `path`      - Base directory where the backup will be created
    /// * `l2_height` - L2 height at which the backup was created
    ///
    /// # Returns
    /// Information about the created backup including block height, path and timestamp
    pub(super) async fn create_backup(
        &self,
        path: Option<PathBuf>,
        ledger_db: &LedgerDB,
    ) -> anyhow::Result<CreateBackupInfo> {
        let backup_path = path
            .as_ref()
            .or(self.base_path.as_ref())
            .context("Missing path and no backup_path found in config.")?;

        let l1_lock = self.l1_processing_lock.lock().await;
        let l2_lock = self.l2_processing_lock.lock().await;

        let l2_height = ledger_db
            .get_head_soft_confirmation_height()?
            .unwrap_or_default();

        let start_time = Instant::now();
        info!("Starting database backup process...");

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        info!(
            "Creating {} backup at path {}",
            self.node_kind,
            backup_path.display()
        );

        let mut handles = Vec::new();

        {
            let dbs = self.databases.read().unwrap();
            for dir in &self.config.backup_dirs {
                let path = backup_path.join(dir);
                let db = dbs.get(dir).context("Missing required db")?.clone();
                db.flush()?;
                handles.push(tokio::task::spawn_blocking(move || db.create_backup(&path)));
            }
        }

        // Wait for all dbs to start backing up under lock before releasing
        drop(l2_lock);
        drop(l1_lock);

        for handle in handles {
            handle.await??;
        }

        if let Err(e) = self.validate_backup(backup_path) {
            warn!("Error validating backup: {e}");
            bail!("Error creating valid backup: {e}");
        }

        let backup_info = self.get_backup_info(backup_path)?;
        let backup_id = backup_info
            .get("ledger")
            .expect("Would fail on validate_backup")
            .last()
            .expect("Would fail on validate_backup")
            .backup_id;

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

    async fn set_metadata<P: AsRef<Path>>(
        &self,
        backup_path: P,
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
                version: 0,
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
    pub fn restore_dbs_from_backup<P: AsRef<Path>>(
        &self,
        db_path: P,
        backup_path: P,
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

        for dir in &self.config.backup_dirs {
            let dir_start = Instant::now();
            info!("Restoring {dir} database");
            let backup_path = backup_path.join(dir);
            let path = tmp_path.join(dir);
            restore_from_backup(path, backup_path)?;
            info!(
                "{dir} database restore completed in {:.2}s",
                dir_start.elapsed().as_secs_f32()
            );
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
    pub(super) fn validate_backup<P: AsRef<Path>>(&self, backup_path: P) -> anyhow::Result<()> {
        let backup_path = backup_path.as_ref();

        if !backup_path.exists() {
            bail!("Backup directory does not exist: {:?}", backup_path);
        }

        let mut sizes = HashSet::new();
        for dir in &self.config.backup_dirs {
            let path = backup_path.join(dir);
            if !path.exists() {
                bail!("Missing required directory '{}' in backup", dir);
            }

            if path.read_dir()?.next().is_none() {
                bail!("Directory '{}' is empty ", dir);
            }

            let backup_size = validate_backup(&path)?;
            sizes.insert(backup_size);
        }

        if sizes.len() != 1 {
            bail!("Backup is corrupted. Each sub-dir should have the same number of incremental backups")
        }

        Ok(())
    }

    pub(super) fn get_backup_info<P: AsRef<Path>>(
        &self,
        backup_path: P,
    ) -> anyhow::Result<HashMap<String, Vec<BackupEngineInfo>>> {
        let backup_path = backup_path.as_ref();
        if !backup_path.exists() {
            bail!("Backup directory does not exist: {:?}", backup_path);
        }

        let mut map = HashMap::new();

        for dir in &self.config.backup_dirs {
            let engine = get_backup_engine(backup_path.join(dir))?;
            map.insert(dir.to_string(), engine.get_backup_info());
        }

        Ok(map)
    }
}
