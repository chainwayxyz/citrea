use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::backup::CreateBackupInfo;
use crate::NodeType;

pub(crate) const METADATA_FILE: &str = ".metadata";
const BACKUP_EXTENSION: &str = "bak";

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub version: u32,
    pub node_type: NodeType,
    pub backups: BTreeMap<u32, u64>, // backup_id -> l1_block_height if node_type is light client prover, otherwise l2_block_height
}

pub(crate) async fn backup_metadata_file(backup_path: &Path) -> anyhow::Result<PathBuf> {
    let metadata_path = backup_path.join(METADATA_FILE);
    let backup_metadata_path = metadata_path.with_extension(BACKUP_EXTENSION);

    if !metadata_path.exists() {
        bail!("Metadata file not found at {}", metadata_path.display());
    }

    tokio::fs::copy(&metadata_path, &backup_metadata_path)
        .await
        .context("Failed to create backup of metadata file")?;

    debug!(
        "Created metadata backup at {}",
        backup_metadata_path.display()
    );

    Ok(backup_metadata_path)
}

pub(crate) async fn update_metadata_after_purge<P: AsRef<Path>>(
    backup_path: P,
    backup_id: u32,
) -> anyhow::Result<()> {
    let metadata_path = backup_path.as_ref().join(METADATA_FILE);
    ensure!(metadata_path.exists(), "Metadata file not found");

    let content = tokio::fs::read_to_string(&metadata_path).await?;
    let mut metadata: BackupMetadata = serde_json::from_str(&content)?;

    metadata.backups.retain(|&id, _| id >= backup_id);

    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    tokio::fs::write(metadata_path, metadata_json).await?;

    Ok(())
}

pub(crate) async fn restore_metadata_backup(backup_path: &Path) -> anyhow::Result<()> {
    let metadata_path = backup_path.join(METADATA_FILE);
    let backup_metadata_path = metadata_path.with_extension(BACKUP_EXTENSION);

    tokio::fs::rename(backup_metadata_path, &metadata_path)
        .await
        .context("Failed to restore metadata from backup")?;

    trace!("Restored original metadata from backup");
    Ok(())
}

pub(crate) async fn remove_metadata_backup(backup_path: &Path) -> anyhow::Result<()> {
    let backup_metadata_path = backup_path
        .join(METADATA_FILE)
        .with_extension(BACKUP_EXTENSION);

    tokio::fs::remove_file(backup_metadata_path)
        .await
        .context("Failed to remove metadata backup")?;

    trace!("Removed metadata backup file");
    Ok(())
}

pub(crate) async fn set_metadata<P: AsRef<Path>>(
    backup_path: P,
    info: &CreateBackupInfo,
    node_type: NodeType,
) -> anyhow::Result<()> {
    let metadata_path = backup_path.as_ref().join(METADATA_FILE);
    let mut metadata = if metadata_path.exists() {
        let content = tokio::fs::read_to_string(&metadata_path).await?;
        serde_json::from_str(&content)?
    } else {
        BackupMetadata {
            node_type,
            backups: BTreeMap::new(),
            version: 0,
        }
    };
    let block_height = {
        match node_type {
            NodeType::Sequencer | NodeType::FullNode | NodeType::BatchProver => {
                info.l2_block_height.unwrap_or(0)
            }
            NodeType::LightClientProver => {
                // Light client prover does not have L2 blocks, so we use L1 height
                info.l1_block_height.unwrap_or(0)
            }
        }
    };
    metadata.backups.insert(info.backup_id, block_height);
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    tokio::fs::write(metadata_path, metadata_json).await?;
    Ok(())
}

pub async fn backup_kind_from_metadata<P: AsRef<Path>>(backup_path: P) -> anyhow::Result<NodeType> {
    let metadata_path = backup_path.as_ref().join(METADATA_FILE);
    ensure!(metadata_path.exists(), "Metadata file not found");

    let content = tokio::fs::read_to_string(&metadata_path).await?;
    let metadata: BackupMetadata = serde_json::from_str(&content)?;

    Ok(metadata.node_type)
}
