//! Metrics collection for the light client prover
//!
//! This module defines metrics that track aspects of light client prover operation,
//! including L1 block processing times and current L1 block number.
use std::sync::LazyLock;

use metrics::Gauge;
use metrics_derive::Metrics;

#[derive(Metrics)]
#[metrics(scope = "light_client_prover")]
/// Collection of metrics for monitoring light client performance and state
pub struct LightClientProverMetrics {
    #[metric(describe = "The height of the last L1 block proved")]
    /// The height of the last L1 block proved
    pub current_l1_block: Gauge,
    /// The duration of scanning and processing a single L1 block
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block_duration_secs: Gauge,
    /// Tracking the time taken to prove a state transition, gauge because one proof is generated per l1 block
    #[metric(describe = "The duration of generating a light client proof")]
    pub proving_time: Gauge,
}

impl LightClientProverMetrics {
    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub fn set_scan_l1_block_duration(&self, duration: f64) {
        self.scan_l1_block_duration_secs.set(duration);
        // also set histogram so we can follow average and quantiles properly
        metrics::histogram!("light_client_prover_scan_l1_block_duration_secs").record(duration);
    }

    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub(crate) fn set_lcp_proving_time(&self, duration: f64) {
        self.proving_time.set(duration);
        // also set histogram so we can follow average and quantiles properly
        metrics::histogram!("light_client_prover_proving_time_histogram").record(duration);
    }
}

/// Light client metrics
pub static LIGHT_CLIENT_METRICS: LazyLock<LightClientProverMetrics> = LazyLock::new(|| {
    LightClientProverMetrics::describe();
    LightClientProverMetrics::default()
});
