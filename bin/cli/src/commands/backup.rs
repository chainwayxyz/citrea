use std::path::PathBuf;

use citrea_common::backup::BackupManager;
use tracing::info;

pub(crate) async fn restore_backup(
    node_kind: String,
    db_path: PathBuf,
    backup_path: PathBuf,
    backup_id: u32,
) -> anyhow::Result<()> {
    info!(
        "Restore backup {} at {} for {} using backup_id {}",
        backup_path.display(),
        db_path.display(),
        node_kind,
        backup_id
    );

    let backup_manager = BackupManager::new(node_kind, None, None);
    backup_manager.restore_dbs_from_backup(db_path, backup_path, backup_id)
}

pub(crate) async fn purge_backup(backup_path: PathBuf, backup_id: u32) -> anyhow::Result<()> {
    info!(
        "Purging backup at {} up to backup_id {}",
        backup_path.display(),
        backup_id
    );

    let node_kind = BackupManager::backup_kind_from_metadata(&backup_path).await?;
    let backup_manager = BackupManager::new(node_kind, None, None);
    backup_manager.purge_backup(backup_path, backup_id).await
}
