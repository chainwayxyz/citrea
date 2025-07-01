//! Metrics collection for the light client prover
//!
//! This module defines metrics that track aspects of light client prover operation,
//! including L1 block processing times and current L1 block number.
use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

#[derive(Metrics)]
#[metrics(scope = "light_client_prover")]
/// Collection of metrics for monitoring light client performance and state
pub struct LightClientProverMetrics {
    #[metric(describe = "The height of the last L1 block proved")]
    /// The height of the last L1 block proved
    pub current_l1_block: Gauge,
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    /// The duration of scanning and processing a single L1 block
    pub scan_l1_block: Histogram,
}

/// Light client metrics
pub static LIGHT_CLIENT_METRICS: Lazy<LightClientProverMetrics> = Lazy::new(|| {
    LightClientProverMetrics::describe();
    LightClientProverMetrics::default()
});
