//! Common RPC crate provides helper methods that are needed in rpc servers
use hyper::Method;
use jsonrpsee::core::RegisterMethodError;
use jsonrpsee::server::middleware::http::ProxyGetRequestLayer;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::schema::types::BatchNumber;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};

// Exit early if head_batch_num is below this threshold
const BLOCK_NUM_THRESHOLD: u64 = 2;

/// Register the healthcheck rpc
pub fn register_healthcheck_rpc<T: Send + Sync + 'static>(
    rpc_methods: &mut RpcModule<T>,
    ledger_db: LedgerDB,
) -> Result<(), RegisterMethodError> {
    let mut rpc = RpcModule::new(ledger_db);

    rpc.register_async_method("health_check", |_, ledger_db, _| async move {
        let error = |msg: &str| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(msg.to_string()),
            )
        };

        let Some((BatchNumber(head_batch_num), _)) = ledger_db
            .get_head_soft_confirmation()
            .map_err(|err| error(&format!("Failed to get head soft batch: {}", err)))?
        else {
            return Ok::<(), ErrorObjectOwned>(());
        };

        // TODO: if the first blocks are not being produced properly, this might cause healthcheck to always return Ok
        if head_batch_num < BLOCK_NUM_THRESHOLD {
            return Ok::<(), ErrorObjectOwned>(());
        }

        let soft_batches = ledger_db
            .get_soft_confirmation_range(
                &(BatchNumber(head_batch_num - 1)..BatchNumber(head_batch_num + 1)),
            )
            .map_err(|err| error(&format!("Failed to get soft batch range: {}", err)))?;

        let block_time_s = (soft_batches[1].timestamp - soft_batches[0].timestamp).max(1);
        tokio::time::sleep(Duration::from_millis(block_time_s * 1500)).await;

        let (new_head_batch_num, _) = ledger_db
            .get_head_soft_confirmation()
            .map_err(|err| error(&format!("Failed to get head soft batch: {}", err)))?
            .unwrap();
        if new_head_batch_num > BatchNumber(head_batch_num) {
            Ok::<(), ErrorObjectOwned>(())
        } else {
            Err(error("Block number is not increasing"))
        }
    })?;

    rpc_methods.merge(rpc)
}

/// Returns health check proxy layer to be used as http middleware
pub fn get_healthcheck_proxy_layer() -> ProxyGetRequestLayer {
    ProxyGetRequestLayer::new("/health", "health_check").unwrap()
}

/// Returns cors layer to be used as http middleware
pub fn get_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any)
}
