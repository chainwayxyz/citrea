//! Common RPC crate provides helper methods that are needed in rpc servers
use std::sync::Arc;
use std::time::Duration;

use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use futures::future::BoxFuture;
use futures::FutureExt;
use hyper::Method;
use jsonrpsee::core::RegisterMethodError;
use jsonrpsee::server::middleware::http::ProxyGetRequestLayer;
use jsonrpsee::server::middleware::rpc::RpcServiceT;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::{ErrorObjectOwned, Request};
use jsonrpsee::{MethodResponse, RpcModule};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::schema::types::L2BlockNumber;
use sov_rollup_interface::services::da::DaService;
use tower_http::cors::{Any, CorsLayer};

mod auth;
pub mod server;
pub mod utils;

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

        let Some((L2BlockNumber(head_batch_num), _)) = ledger_db
            .get_head_l2_block()
            .map_err(|err| error(&format!("Failed to get head l2 block: {}", err)))?
        else {
            return Ok::<(), ErrorObjectOwned>(());
        };

        if head_batch_num < BLOCK_NUM_THRESHOLD {
            return Ok::<(), ErrorObjectOwned>(());
        }

        let l2_blocks = ledger_db
            .get_l2_block_range(
                &(L2BlockNumber(head_batch_num - 1)..=L2BlockNumber(head_batch_num)),
            )
            .map_err(|err| error(&format!("Failed to get l2 block range: {}", err)))?;

        let block_time_s = (l2_blocks[1].timestamp - l2_blocks[0].timestamp).max(1);
        tokio::time::sleep(Duration::from_millis(block_time_s * 1500)).await;

        let (new_head_batch_num, _) = ledger_db
            .get_head_l2_block()
            .map_err(|err| error(&format!("Failed to get head l2 block: {}", err)))?
            .unwrap();
        if new_head_batch_num > L2BlockNumber(head_batch_num) {
            Ok::<(), ErrorObjectOwned>(())
        } else {
            Err(error("Block number is not increasing"))
        }
    })?;

    rpc_methods.merge(rpc)
}

/// Register the healthcheck rpc
pub fn register_healthcheck_rpc_light_client_prover<T: Send + Sync + 'static, Da: DaService>(
    rpc_methods: &mut RpcModule<T>,
    da_service: Arc<Da>,
) -> Result<(), RegisterMethodError> {
    let mut rpc = RpcModule::new(da_service.clone());

    rpc.register_async_method("health_check", |_, da_service, _| async move {
        let error = |msg: &str| {
            ErrorObjectOwned::owned(
                INTERNAL_ERROR_CODE,
                INTERNAL_ERROR_MSG,
                Some(msg.to_string()),
            )
        };

        let exponential_backoff = ExponentialBackoff {
            max_elapsed_time: Some(Duration::from_secs(120)),
            ..Default::default()
        };

        let res = retry_backoff(exponential_backoff.clone(), || {
            let da_service = da_service.clone();
            async move {
                da_service.get_head_block_header().await.map_err(|e| {
                    let e = e;
                    backoff::Error::transient(e)
                })
            }
        })
        .await;
        match res {
            Ok(_) => Ok::<(), ErrorObjectOwned>(()),
            Err(e) => Err(error(&format!(
                "Failed to retrieve head block header: {}",
                e
            ))),
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

#[derive(Debug, Clone)]
pub struct Logger<S>(pub S);

impl<'a, S> RpcServiceT<'a> for Logger<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let req_id = req.id();
        let req_method = req.method_name().to_string();

        tracing::debug!(id = ?req_id, method = ?req_method, params = ?req.params().as_str(), "rpc_request");

        let service = self.0.clone();
        async move {
            let resp = service.call(req).await;
            if resp.is_success() {
                tracing::trace!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_success");
            } else {
                match req_method.as_str() {
                    "eth_sendRawTransaction" => tracing::debug!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_error"),
                    _ => tracing::warn!(id = ?req_id, method = ?req_method, result = ?resp.as_result(), "rpc_error")
                }

            }

            resp
        }
        .boxed()
    }
}
