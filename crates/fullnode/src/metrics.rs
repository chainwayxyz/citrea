//! Metrics collection for the fullnode
//!
//! This module defines metrics that track various aspects of fullnode operation,
//! including block processing times and current block numbers.

use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

/// Collection of metrics for monitoring fullnode performance and state
#[derive(Metrics)]
#[metrics(scope = "fullnode")]
pub struct FullnodeMetrics {
    /// Current L1 block number that has been processed by the fullnode
    #[metric(describe = "The current L1 block number which is used to produce L2 blocks")]
    pub current_l1_block: Gauge,

    /// Current L2 block number which has been processed by the fullnode
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,

    /// Histogram tracking the time taken to scan and process L1 blocks
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block: Histogram,

    /// Histogram tracking the time taken to process L2 blocks
    #[metric(describe = "The duration of processing a single l2 block")]
    pub process_l2_block: Histogram,
}

/// Global instance of fullnode metrics
///
/// This static variable provides access to all fullnode metrics through a lazy-initialized
/// singleton pattern. The metrics are automatically described and initialized on first access.
pub static FULLNODE_METRICS: Lazy<FullnodeMetrics> = Lazy::new(|| {
    FullnodeMetrics::describe();
    FullnodeMetrics::default()
});
