use std::path::PathBuf;

use citrea_common::backup::BackupManager;
use tracing::info;

pub(crate) async fn restore_backup(
    node_kind: String,
    db_path: PathBuf,
    backup_path: PathBuf,
) -> anyhow::Result<()> {
    info!(
        "Restore backup {} at {} for {}",
        backup_path.display(),
        db_path.display(),
        node_kind
    );

    let backup_manager = BackupManager::new(node_kind, None, None);
    backup_manager.restore_dbs_from_backup(db_path, backup_path)
}
