use std::path::PathBuf;

use citrea_common::backup::metadata::backup_kind_from_metadata;
use citrea_common::backup::BackupManager;
use citrea_common::NodeType;
use tracing::info;

pub(crate) async fn restore_backup(
    node_type: NodeType,
    db_path: PathBuf,
    backup_path: PathBuf,
    backup_id: u32,
) -> anyhow::Result<()> {
    info!(
        "Restore backup {} at {} for {} using backup_id {}",
        backup_path.display(),
        db_path.display(),
        node_type,
        backup_id
    );

    let backup_manager = BackupManager::new(node_type, None, None);
    backup_manager.restore_dbs_from_backup(db_path, backup_path, backup_id)
}

pub(crate) async fn purge_backup(
    backup_path: PathBuf,
    num_to_keep: Option<u32>,
    backup_id: Option<u32>,
) -> anyhow::Result<()> {
    info!("Purging backup at {}", backup_path.display(),);

    let node_type = backup_kind_from_metadata(&backup_path).await?;
    let backup_manager = BackupManager::new(node_type, None, None);
    backup_manager
        .purge_backup(backup_path, num_to_keep, backup_id)
        .await
}
