use std::path::PathBuf;

use citrea_common::backup::BackupManager;
use citrea_storage_ops::types::NodeKind;
use tracing::info;

pub(crate) async fn restore_backup(
    node_kind: NodeKind,
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
