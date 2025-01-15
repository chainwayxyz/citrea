use std::path::PathBuf;
use std::sync::Arc;

use jsonrpsee::core::RegisterMethodError;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use serde::Serialize;

use super::BackupManager;

#[derive(Debug, Clone, Serialize)]
pub struct ValidationResponse {
    /// Path that was validated
    pub backup_path: PathBuf,
    /// Whether the backup at the path is valid
    pub is_valid: bool,
    /// Error message if validation failed
    pub message: Option<String>,
}

pub fn register_backup_rpc<T>(
    rpc_methods: &mut RpcModule<T>,
    backup_manager: Arc<BackupManager>,
) -> Result<(), RegisterMethodError>
where
    T: Send + Sync + 'static,
{
    let mut rpc_module = RpcModule::new(backup_manager);

    rpc_module
        .register_async_method(
            "create_backup",
            move |params, backup_manager, _| async move {
                let path: PathBuf = params.one().map_err(|e| {
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        "Invalid backup path parameter",
                        Some(format!("{e}",)),
                    )
                })?;

                backup_manager.create_backup(path).await.map_err(|e| {
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("{e}",)),
                    )
                })
            },
        )
        .expect("Failed to register create_backup RPC method");

    rpc_module
        .register_async_method("validate_backup", move |params, _, _| async move {
            let path: PathBuf = params.one().map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    "Invalid backup path parameter",
                    Some(format!("{e}",)),
                )
            })?;

            let res = match BackupManager::validate_backup(&path) {
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
            Ok::<ValidationResponse, ErrorObjectOwned>(res)
        })
        .expect("Failed to register validate_backup RPC method");

    rpc_methods.merge(rpc_module)
}
