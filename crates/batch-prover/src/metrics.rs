//! Metrics collection for the batch prover
//!
//! This module defines metrics that track various aspects of batch prover operation,
//! including block processing times and current block numbers.

use std::sync::LazyLock;

use metrics::{histogram, Gauge, Histogram};
use metrics_derive::Metrics;

/// Collection of metrics for monitoring batch prover performance and state
/// Also note the struct methods below will be recording to histogram for some metrics as well
#[derive(Metrics)]
#[metrics(scope = "batch_prover")]
pub struct BatchProverMetrics {
    /// Latest L1 block number that has been processed by the batch prover
    #[metric(describe = "Latest L1 block number that has been processed by the batch prover")]
    pub current_l1_block: Gauge,

    /// Current L2 block number that has been processed by the batch prover
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,

    /// Histogram tracking the time taken to process L2 blocks
    #[metric(describe = "The duration of processing a single l2 block")]
    pub process_l2_block: Histogram,

    /// Gauge tracking the time taken to scan and process a single L1 block
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block_duration_secs: Gauge,

    /// Histogram tracking the time taken to prepare input for a batch proof
    #[metric(describe = "The duration of the entire input preparation process for a batch proof")]
    pub total_input_preparation_time: Histogram,

    /// Histogram tracking the time taken to generate cumulative witness
    #[metric(describe = "The cumulative witness generation time for a batch proof")]
    pub cumulative_witness_generation_time: Histogram,

    /// State log cache size in witness generation
    #[metric(describe = "The size of the state log cache in witness generation")]
    pub state_log_cache_size: Histogram,

    /// Offchain log cache size in witness generation
    #[metric(describe = "The size of the offchain log cache in witness generation")]
    pub offchain_log_cache_size: Histogram,

    /// Histogram tracking the time taken to prove a state transition
    #[metric(describe = "The duration of generating a batch proof")]
    pub proving_time: Histogram,
}

impl BatchProverMetrics {
    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub fn set_scan_l1_block_duration(&self, duration: f64) {
        self.scan_l1_block_duration_secs.set(duration);
        // also set histogram so we can follow average and quantiles properly
        histogram!("batch_prover_scan_l1_block_duration_secs_histogram").record(duration);
    }
}

/// Batch prover metrics
pub static BATCH_PROVER_METRICS: LazyLock<BatchProverMetrics> = LazyLock::new(|| {
    BatchProverMetrics::describe();
    BatchProverMetrics::default()
});
