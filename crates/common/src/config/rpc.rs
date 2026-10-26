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

#[inline]
const fn default_timeout() -> u64 {
    30
}

#[inline]
const fn default_enable_js_tracer() -> bool {
    true
}

#[inline]
const fn default_proving_jobs_limit() -> usize {
    100
}

#[inline]
const fn default_enable_filters() -> bool {
    true
}

#[inline]
const fn default_max_sync_send_timeout_ms() -> u64 {
    20_000
}

#[inline]
const fn default_trace_memory_limit_mb() -> u64 {
    512
}

#[inline]
const fn default_trace_cache_limit_mb() -> u64 {
    512
}

#[inline]
const fn default_max_tracing_requests() -> usize {
    4
}

#[inline]
const fn default_gas_cap() -> u64 {
    // Keep in sync with `citrea_evm::RPC_DEFAULT_GAS_CAP`.
    100_000_000
}

/// RPC configuration.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
    /// Maximum number of L2 blocks to be traced with debug_traceChain
    pub trace_chain_block_limit: Option<u64>,
    /// Approximate memory a single debug_trace* request may retain, in megabytes, shared by every
    /// transaction it traces. The trace is aborted with an error once it is exceeded. 0 disables
    /// the limit.
    #[serde(default = "default_trace_memory_limit_mb")]
    pub trace_memory_limit_mb: u64,
    /// Megabytes of block traces to keep in the debug_trace* cache.
    #[serde(default = "default_trace_cache_limit_mb")]
    pub trace_cache_limit_mb: u64,
    /// Maximum number of debug_trace* requests executing at the same time; the rest queue.
    /// Together with `trace_memory_limit_mb` this bounds the memory tracing can use at once.
    #[serde(default = "default_max_tracing_requests")]
    pub max_tracing_requests: usize,
    /// Gas cap for `eth_call` and `debug_traceCall`, decoupled from the block gas limit so complex
    /// read-only calls can run above it while still bounding EVM memory and CPU per call. Each RPC
    /// server owns an immutable `citrea_evm::RpcGasCap` constructed from this value and passes it
    /// explicitly to the EVM helpers, independently of other servers. Clamped to at most
    /// `citrea_evm::RPC_DEFAULT_GAS_CAP` (100M): a larger value is capped down to it. 0 means "do
    /// not raise above the block gas limit". Defaults to 100M.
    #[serde(default = "default_gas_cap")]
    pub gas_cap: u64,
    /// Duration after which a filter is considered stale and removed
    pub stale_filter_ttl: Option<usize>,
    /// Maximum number of responded proving jobs in RPC batchProver_getProvingJobs
    #[serde(default = "default_proving_jobs_limit")]
    pub proving_jobs_limit: usize,
    /// RPC timeout in secs
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Enable JS tracer in debug endpoints
    #[serde(default = "default_enable_js_tracer")]
    pub enable_js_tracer: bool,
    /// Enable filter RPCs
    #[serde(default = "default_enable_filters")]
    pub enable_filters: bool,
    /// Maximum timeout in milliseconds for eth_sendRawTransactionSync (EIP-7966) (defaults to 20 seconds)
    /// This should be kept below timeout in order not to hit default timeout error.
    #[serde(default = "default_max_sync_send_timeout_ms")]
    pub max_sync_send_timeout_ms: u64,
    /// API key for protected JSON-RPC methods
    pub api_key: Option<String>,
}

// Hand-written instead of derived: a derived `Default` fills every field with the type's own
// default, which for the numeric fields is 0. That silently ignores the `#[serde(default = ...)]`
// attributes (they only run when deserializing a config that omits the field), so a derived
// `Default` would set `trace_memory_limit_mb: 0` (unlimited tracing) and `trace_cache_limit_mb: 0`
// (a permanently empty cache). This impl mirrors the serde defaults so the two agree.
impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_host: String::new(),
            bind_port: 0,
            max_connections: default_max_connections(),
            max_request_body_size: default_max_request_body_size(),
            max_response_body_size: default_max_response_body_size(),
            batch_requests_limit: default_batch_requests_limit(),
            enable_subscriptions: default_enable_subscriptions(),
            max_subscriptions_per_connection: default_max_subscriptions_per_connection(),
            trace_chain_block_limit: None,
            trace_memory_limit_mb: default_trace_memory_limit_mb(),
            trace_cache_limit_mb: default_trace_cache_limit_mb(),
            max_tracing_requests: default_max_tracing_requests(),
            gas_cap: default_gas_cap(),
            stale_filter_ttl: None,
            proving_jobs_limit: default_proving_jobs_limit(),
            timeout: default_timeout(),
            enable_js_tracer: default_enable_js_tracer(),
            enable_filters: default_enable_filters(),
            max_sync_send_timeout_ms: default_max_sync_send_timeout_ms(),
            api_key: None,
        }
    }
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
            trace_chain_block_limit: read_env("RPC_TRACE_CHAIN_BLOCK_LIMIT")
                .ok()
                .and_then(|val| val.parse().ok()),
            trace_memory_limit_mb: read_env("RPC_TRACE_MEMORY_LIMIT_MB")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_trace_memory_limit_mb),
            trace_cache_limit_mb: read_env("RPC_TRACE_CACHE_LIMIT_MB")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_trace_cache_limit_mb),
            max_tracing_requests: read_env("RPC_MAX_TRACING_REQUESTS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_tracing_requests),
            gas_cap: read_env("RPC_GAS_CAP")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_gas_cap),
            stale_filter_ttl: read_env("RPC_STALE_FILTER_TTL")
                .ok()
                .and_then(|s| s.parse().ok()),
            proving_jobs_limit: read_env("RPC_PROVING_JOBS_LIMIT")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_proving_jobs_limit),
            timeout: read_env("RPC_TIMEOUT")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_timeout),
            enable_js_tracer: read_env("RPC_ENABLE_JS_TRACER")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_enable_js_tracer),
            enable_filters: read_env("RPC_ENABLE_FILTERS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_enable_filters),
            max_sync_send_timeout_ms: read_env("RPC_MAX_SYNC_SEND_TIMEOUT_MS")
                .ok()
                .and_then(|val| val.parse().ok())
                .unwrap_or_else(default_max_sync_send_timeout_ms),
            api_key: read_env("RPC_API_KEY").ok(),
        })
    }
}

// Custom implementation to avoid printing the api_key field
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
            .field("trace_chain_block_limit", &self.trace_chain_block_limit)
            .field("trace_memory_limit_mb", &self.trace_memory_limit_mb)
            .field("trace_cache_limit_mb", &self.trace_cache_limit_mb)
            .field("max_tracing_requests", &self.max_tracing_requests)
            .field("gas_cap", &self.gas_cap)
            .field("stale_filter_ttl", &self.stale_filter_ttl)
            .field("proving_jobs_limit", &self.proving_jobs_limit)
            .field("timeout", &self.timeout)
            .field("enable_filters", &self.enable_filters)
            .field("max_sync_send_timeout_ms", &self.max_sync_send_timeout_ms)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RpcConfig::default()` must apply the same tracing limits as a config file that omits them.
    /// A derived `Default` would zero these, which means unlimited tracing and a dead cache.
    #[test]
    fn default_applies_tracing_limits_not_zero() {
        let cfg = RpcConfig::default();
        assert_eq!(cfg.trace_memory_limit_mb, default_trace_memory_limit_mb());
        assert_eq!(cfg.trace_cache_limit_mb, default_trace_cache_limit_mb());
        assert_eq!(cfg.max_tracing_requests, default_max_tracing_requests());
        assert_eq!(cfg.gas_cap, default_gas_cap());
        // the bug this guards against: 0 means "unlimited" / "empty cache"
        assert_ne!(cfg.trace_memory_limit_mb, 0);
        assert_ne!(cfg.trace_cache_limit_mb, 0);

        // `Default` and a fully-defaulted deserialization must agree on every serde-defaulted field
        let from_empty_toml: RpcConfig =
            toml::from_str("bind_host = \"\"\nbind_port = 0\n").unwrap();
        assert_eq!(cfg, from_empty_toml);
    }
}
