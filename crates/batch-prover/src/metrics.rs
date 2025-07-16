//! Metrics collection for the batch prover
//!
//! This module defines metrics that track various aspects of batch prover operation,
//! including block processing times and current block numbers.

use std::sync::LazyLock;

use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;

/// Collection of metrics for monitoring batch prover performance and state
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

    /// Histogram tracking the time taken to scan and process L1 blocks
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block: Histogram,
}

/// Batch prover metrics
pub static BATCH_PROVER_METRICS: LazyLock<BatchProverMetrics> = LazyLock::new(|| {
    BatchProverMetrics::describe();
    BatchProverMetrics::default()
});
