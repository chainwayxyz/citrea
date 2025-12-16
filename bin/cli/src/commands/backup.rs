use std::path::PathBuf;
use std::sync::Arc;

use citrea_common::backup::metadata::backup_kind_from_metadata;
use citrea_common::backup::{BackupManager, CreateBackupInfo};
use citrea_common::NodeType;
use sov_db::ledger_db::LedgerDB;
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;
use tracing::info;

use crate::commands::{cfs_from_node_type, NodeTypeArg};

pub(crate) async fn create_backup(
    node_type: NodeTypeArg,
    db_path: PathBuf,
    backup_path: PathBuf,
) -> anyhow::Result<CreateBackupInfo> {
    info!(
        "Create backup {} at {} for {}.",
        backup_path.display(),
        db_path.display(),
        node_type,
    );

    let column_families = cfs_from_node_type(node_type);
    let rocksdb_config = RocksdbConfig::new(&db_path, None, Some(column_families));
    let ledger_db = LedgerDB::with_config(&rocksdb_config)?;
    let state_db = Arc::new(StateDB::setup_schema_db(&rocksdb_config)?);
    let native_db = Arc::new(NativeDB::setup_schema_db(&rocksdb_config)?);

    let backup_manager = BackupManager::new(node_type.into(), None, None);
    backup_manager
        .register_database(LedgerDB::DB_PATH_SUFFIX.to_string(), ledger_db.db_handle())?;
    backup_manager.register_database(StateDB::DB_PATH_SUFFIX.to_string(), state_db)?;
    backup_manager.register_database(NativeDB::DB_PATH_SUFFIX.to_string(), native_db)?;

    backup_manager
        .create_backup(Some(backup_path), &ledger_db)
        .await
}

pub(crate) async fn validate_backup(backup_path: PathBuf) -> anyhow::Result<()> {
    let kind = backup_kind_from_metadata(&backup_path).await?;

    info!(
        "Validating backup at {} for {}.",
        backup_path.display(),
        kind,
    );

    let backup_manager = BackupManager::new(kind, None, None);

    backup_manager.validate_backup(&backup_path)
}

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
