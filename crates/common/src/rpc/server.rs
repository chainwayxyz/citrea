use std::net::SocketAddr;

use jsonrpsee::server::{BatchRequestConfig, RpcServiceBuilder, ServerBuilder};
use jsonrpsee::RpcModule;
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::tasks::manager::{TaskManager, TaskType};
use crate::RpcConfig;

/// Starts a RPC server with provided rpc methods.
pub fn start_rpc_server(
    rpc_config: RpcConfig,
    task_manager: &mut TaskManager<()>,
    methods: RpcModule<()>,
    channel: Option<oneshot::Sender<SocketAddr>>,
) {
    let bind_host = match rpc_config.bind_host.parse() {
        Ok(bind_host) => bind_host,
        Err(e) => {
            error!("Failed to parse bind host: {}", e);
            return;
        }
    };
    let listen_address = SocketAddr::new(bind_host, rpc_config.bind_port);

    let max_connections = rpc_config.max_connections;
    let max_subscriptions_per_connection = rpc_config.max_subscriptions_per_connection;
    let max_request_body_size = rpc_config.max_request_body_size;
    let max_response_body_size = rpc_config.max_response_body_size;
    let batch_requests_limit = rpc_config.batch_requests_limit;

    let middleware = tower::ServiceBuilder::new()
        .layer(super::get_cors_layer())
        .layer(super::get_healthcheck_proxy_layer());

    let rpc_middleware = RpcServiceBuilder::new()
        .layer_fn(move |s| super::auth::Auth::new(s, rpc_config.api_key.clone()))
        .layer_fn(super::Logger);

    task_manager.spawn(TaskType::Secondary, move |cancellation_token| async move {
        let server = ServerBuilder::default()
            .max_connections(max_connections)
            .max_subscriptions_per_connection(max_subscriptions_per_connection)
            .max_request_body_size(max_request_body_size)
            .max_response_body_size(max_response_body_size)
            .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
            .set_http_middleware(middleware)
            .set_rpc_middleware(rpc_middleware)
            .build([listen_address].as_ref())
            .await;

        match server {
            Ok(server) => {
                let bound_address = match server.local_addr() {
                    Ok(address) => address,
                    Err(e) => {
                        error!("{}", e);
                        return;
                    }
                };
                if let Some(channel) = channel {
                    if let Err(e) = channel.send(bound_address) {
                        error!("Could not send bound_address {}: {}", bound_address, e);
                        return;
                    }
                }
                info!("Starting RPC server at {} ", &bound_address);

                let _server_handle = server.start(methods);
                cancellation_token.cancelled().await;
            }
            Err(e) => {
                error!("Could not start RPC server: {}", e);
            }
        }
    });
}
