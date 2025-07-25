use std::sync::LazyLock;

use metrics::Gauge;
use metrics_derive::Metrics;

/// This defines the struct which encapsulates all metrics used for Evm.
#[derive(Metrics)]
#[metrics(scope = "evm")]
pub struct EvmMetrics {
    /// Current Block gas usage
    #[metric(describe = "Current Block Gas Usage")]
    pub(crate) block_gas_usage: Gauge,
    /// Current Block Base Fee in Gwei
    #[metric(describe = "Current Base Fee per Gas in Gwei")]
    pub(crate) block_base_fee: Gauge,
}

/// EVM metrics
pub static EVM_METRICS: LazyLock<EvmMetrics> = LazyLock::new(|| {
    EvmMetrics::describe();
    EvmMetrics::default()
});
