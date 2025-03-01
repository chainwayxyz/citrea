use std::path::Path;

use anyhow::bail;
use rocksdb::backup::{self, BackupEngine};
use tracing::info;

pub(super) fn restore_from_backup(
    db_path: impl AsRef<Path>,
    backup_path: impl AsRef<Path>,
    backup_id: u32,
) -> anyhow::Result<()> {
    let db_path = db_path.as_ref();
    let backup_path = backup_path.as_ref();
    if db_path.exists() {
        bail!("Should restore to a non-existing temp directory");
    }
    std::fs::create_dir_all(db_path)?;

    let mut backup_engine = get_backup_engine(backup_path)?;
    let backups = backup_engine.get_backup_info();
    if backups.is_empty() {
        bail!("No backups found for {} in {:?}", "ledgerdb", backup_path);
    }

    let restore_options = rocksdb::backup::RestoreOptions::default();
    backup_engine.restore_from_latest_backup(db_path, db_path, &restore_options)?;

    backup_engine.restore_from_backup(db_path, db_path, &restore_options, backup_id);

    info!(
        path = ?backup_path,
        "Restored database from backup"
    );

    Ok(())
}

pub(super) fn validate_backup(backup_path: impl AsRef<Path>) -> anyhow::Result<usize> {
    let backup_path = backup_path.as_ref();
    if !backup_path.exists() {
        bail!("Backup directory does not exist at {:?}", backup_path);
    }

    let backup_engine = get_backup_engine(backup_path)?;
    let backups = backup_engine.get_backup_info();
    if backups.is_empty() {
        bail!("No backups found in {:?}", backup_path);
    }

    for backup_info in &backups {
        let backup_id = backup_info.backup_id;

        // Basic backup ID and size checks
        if backup_id == 0 {
            bail!("Invalid backup ID: 0");
        }
        if backup_info.size == 0 {
            bail!("Backup {} has size 0", backup_id);
        }
        if backup_info.num_files == 0 {
            bail!("Backup {} has no files", backup_id);
        }

        let meta_dir = backup_path.join("meta").join(backup_id.to_string());
        if !meta_dir.exists() {
            bail!("Missing metadata directory for backup {}", backup_id);
        }

        let private_dir = backup_path.join("private").join(backup_id.to_string());
        if !private_dir.exists() {
            bail!("Missing private directory for backup {}", backup_id);
        }

        let shared_dir = backup_path.join("shared_checksum");
        if !shared_dir.exists() {
            bail!("Missing shared_checksum directory for backup {}", backup_id);
        }

        backup_engine.verify_backup(backup_id)?;
    }
    Ok(backups.len())
}

pub(super) fn get_backup_engine(backup_path: impl AsRef<Path>) -> anyhow::Result<BackupEngine> {
    let backup_opts = rocksdb::backup::BackupEngineOptions::new(backup_path)?;
    let env = rocksdb::Env::new()?;
    let engine = rocksdb::backup::BackupEngine::open(&backup_opts, &env)?;
    Ok(engine)
}
