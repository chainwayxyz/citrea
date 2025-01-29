use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::LedgerDB;

use super::job::{BackupJob, JobManager};
use super::BackupManager;

/// Response from backup validation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
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
    #[method(name = "jobCreate")]
    async fn backup_job_create(&self, path: Option<PathBuf>) -> RpcResult<u32>;

    #[method(name = "jobStatus")]
    async fn backup_job_status(&self, job_id: u32) -> RpcResult<Option<BackupJob>>;

    #[method(name = "jobList")]
    async fn backup_job_list(&self) -> RpcResult<Vec<BackupJob>>;

    #[method(name = "validate")]
    async fn backup_validate(&self, path: PathBuf) -> RpcResult<ValidationResponse>;

    #[method(name = "info")]
    async fn backup_info(
        &self,
        path: PathBuf,
    ) -> RpcResult<HashMap<String, Vec<BackupInfoResponse>>>;
}

pub struct BackupRpcServerImpl {
    job_manager: Arc<JobManager>,
    backup_manager: Arc<BackupManager>,
}

impl BackupRpcServerImpl {
    pub fn new(backup_manager: Arc<BackupManager>, ledger_db: LedgerDB) -> Self {
        Self {
            job_manager: Arc::new(JobManager::new(backup_manager.clone(), ledger_db)),
            backup_manager,
        }
    }
}

#[async_trait::async_trait]
impl BackupRpcServer for BackupRpcServerImpl {
    async fn backup_job_create(&self, path: Option<PathBuf>) -> RpcResult<u32> {
        self.job_manager
            // .create_backup(path, l2_height)
            .create_backup_job(path)
            .await
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}")),
                )
            })
    }

    async fn backup_job_status(&self, job_id: u32) -> RpcResult<Option<BackupJob>> {
        Ok(self.job_manager.get_job_status(job_id).await)
    }

    async fn backup_job_list(&self) -> RpcResult<Vec<BackupJob>> {
        Ok(self.job_manager.list_jobs().await)
    }

    async fn backup_validate(&self, path: PathBuf) -> RpcResult<ValidationResponse> {
        let res = match self.backup_manager.validate_backup(&path) {
            Ok(()) => ValidationResponse {
                backup_path: path,
                is_valid: true,
                message: None,
            },
            Err(e) => ValidationResponse {
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
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}")),
                )
            })
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
