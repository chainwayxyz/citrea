use std::fmt;

use serde::{Deserialize, Serialize};
use sov_ledger_rpc::server::LedgerRpcServerConfig;

use crate::utils::read_env;
use crate::FromEnv;

#[inline]
const fn default_max_connections() -> u32 {
    100
}

#[inline]
pub(super) const fn default_max_request_body_size() -> u32 {
    10 * 1024 * 1024
}

#[inline]
pub(super) const fn default_max_response_body_size() -> u32 {
    10 * 1024 * 1024
}

#[inline]
pub(super) const fn default_batch_requests_limit() -> u32 {
    50
}

#[inline]
const fn default_enable_subscriptions() -> bool {
    true
}

#[inline]
const fn default_max_subscriptions_per_connection() -> u32 {
    100
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Default, Serialize)]
pub struct RpcConfig {
    /// RPC host.
    pub bind_host: String,
    /// RPC port.
    pub bind_port: u16,
    /// Maximum number of concurrent requests.
    /// if not set defaults to 100.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Max request body request
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u32,
    /// Max response body request
    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: u32,
    /// Maximum number of batch requests
    #[serde(default = "default_batch_requests_limit")]
    pub batch_requests_limit: u32,
    /// Disable subscription RPCs
    #[serde(default = "default_enable_subscriptions")]
    pub enable_subscriptions: bool,
    /// Maximum number of subscription connections
    #[serde(default = "default_max_subscriptions_per_connection")]
    pub max_subscriptions_per_connection: u32,
    /// API key for protected JSON-RPC methods
    pub api_key: Option<String>,
}

impl From<RpcConfig> for LedgerRpcServerConfig {
    fn from(val: RpcConfig) -> Self {
        LedgerRpcServerConfig {
            max_l2_blocks_per_request: val.batch_requests_limit,
        }
    }
}

impl FromEnv for RpcConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            bind_host: read_env("RPC_BIND_HOST")?,
            bind_port: read_env("RPC_BIND_PORT")?.parse()?,
            // for the rest of the fields, in case of a parsing error, the default value will be used
            max_connections: read_env("RPC_MAX_CONNECTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_connections),
            max_request_body_size: read_env("RPC_MAX_REQUEST_BODY_SIZE")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_request_body_size),
            max_response_body_size: read_env("RPC_MAX_RESPONSE_BODY_SIZE")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_response_body_size),
            batch_requests_limit: read_env("RPC_BATCH_REQUESTS_LIMIT")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_batch_requests_limit),
            enable_subscriptions: read_env("RPC_ENABLE_SUBSCRIPTIONS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_enable_subscriptions),
            max_subscriptions_per_connection: read_env("RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_subscriptions_per_connection),
            api_key: read_env("RPC_API_KEY").ok(),
        })
    }
}

impl fmt::Display for RpcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RpcConfig")
            .field("bind_host", &self.bind_host)
            .field("bind_port", &self.bind_port)
            .field("max_connections", &self.max_connections)
            .field("max_request_body_size", &self.max_request_body_size)
            .field("max_response_body_size", &self.max_response_body_size)
            .field("batch_requests_limit", &self.batch_requests_limit)
            .field("enable_subscriptions", &self.enable_subscriptions)
            .field(
                "max_subscriptions_per_connection",
                &self.max_subscriptions_per_connection,
            )
            .finish()
    }
}
