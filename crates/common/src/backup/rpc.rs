use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::LedgerDB;

use super::{BackupManager, CreateBackupInfo};
use crate::rpc::utils::internal_rpc_error;

/// Response from backup validation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupValidationResponse {
    /// Path that was validated
    pub backup_path: PathBuf,
    /// Whether the backup at the path is valid
    pub is_valid: bool,
    /// Error message if validation failed
    pub message: Option<String>,
}

/// Information about a specific backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupInfoResponse {
    /// Timestamp of the backup
    pub timestamp: i64,
    /// ID of the backup
    pub backup_id: u32,
    /// Size of the backup
    pub size: u64,
    /// Number of files related to the backup
    pub num_files: u32,
}

#[rpc(client, server, namespace = "backup")]
pub trait BackupRpc {
    #[method(name = "create")]
    async fn backup_create(
        &self,
        path: Option<PathBuf>,
        n_to_keep: Option<u32>,
    ) -> RpcResult<CreateBackupInfo>;

    #[method(name = "validate")]
    async fn backup_validate(&self, path: PathBuf) -> RpcResult<BackupValidationResponse>;

    #[method(name = "info")]
    async fn backup_info(
        &self,
        path: PathBuf,
    ) -> RpcResult<HashMap<String, Vec<BackupInfoResponse>>>;
}

pub struct BackupRpcServerImpl {
    backup_manager: Arc<BackupManager>,
    ledger_db: LedgerDB,
}

impl BackupRpcServerImpl {
    pub fn new(backup_manager: Arc<BackupManager>, ledger_db: LedgerDB) -> Self {
        Self {
            backup_manager,
            ledger_db,
        }
    }
}

#[async_trait::async_trait]
impl BackupRpcServer for BackupRpcServerImpl {
    async fn backup_create(
        &self,
        path: Option<PathBuf>,
        n_to_keep: Option<u32>,
    ) -> RpcResult<CreateBackupInfo> {
        let result = self
            .backup_manager
            .create_backup(path, &self.ledger_db)
            .await
            .map_err(internal_rpc_error)?;

        if let Some(n_to_keep) = n_to_keep {
            self.backup_manager
                .purge_backup(result.backup_path.clone(), Some(n_to_keep), None)
                .await
                .map_err(internal_rpc_error)?;
        }

        Ok(result)
    }

    async fn backup_validate(&self, path: PathBuf) -> RpcResult<BackupValidationResponse> {
        let res = match self.backup_manager.validate_backup(&path) {
            Ok(()) => BackupValidationResponse {
                backup_path: path,
                is_valid: true,
                message: None,
            },
            Err(e) => BackupValidationResponse {
                backup_path: path,
                is_valid: false,
                message: Some(e.to_string()),
            },
        };
        Ok(res)
    }

    async fn backup_info(
        &self,
        path: PathBuf,
    ) -> RpcResult<HashMap<String, Vec<BackupInfoResponse>>> {
        self.backup_manager
            .get_backup_info(path)
            .map(|info| {
                info.into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            v.into_iter()
                                .map(|v| BackupInfoResponse {
                                    timestamp: v.timestamp,
                                    backup_id: v.backup_id,
                                    size: v.size,
                                    num_files: v.num_files,
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect()
            })
            .map_err(internal_rpc_error)
    }
}

pub fn create_backup_rpc_module(
    ledger_db: LedgerDB,
    backup_manager: Arc<BackupManager>,
) -> jsonrpsee::RpcModule<BackupRpcServerImpl>
where
    BackupRpcServerImpl: BackupRpcServer,
{
    let server = BackupRpcServerImpl::new(backup_manager, ledger_db);
    BackupRpcServer::into_rpc(server)
}
