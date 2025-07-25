//! Metrics collection for the fullnode
//!
//! This module defines metrics that track various aspects of fullnode operation,
//! including block processing times and current block numbers.

use std::sync::LazyLock;

use metrics::{histogram, Gauge, Histogram};
use metrics_derive::Metrics;

/// Collection of metrics for monitoring fullnode performance and state
#[derive(Metrics)]
#[metrics(scope = "fullnode")]
pub struct FullnodeMetrics {
    /// Latest L1 block number that has been processed by the fullnode
    #[metric(describe = "Latest L1 block number that has been processed by the fullnode")]
    pub current_l1_block: Gauge,

    /// Current L2 block number which has been processed by the fullnode
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,

    /// Gauge tracking the time taken to scan and process L1 blocks
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block_duration_secs: Gauge,

    /// Histogram tracking the time taken to process L2 blocks
    #[metric(describe = "The duration of processing a single l2 block")]
    pub process_l2_block: Histogram,

    /// Histogram tracking the time taken to process sequencer commitments
    #[metric(describe = "The duration of processing a sequencer commitment")]
    pub sequencer_commitment_processing_time: Histogram,

    /// Histogram tracking the time taken to process batch proofs
    #[metric(describe = "The duration of processing a batch proof")]
    pub batch_proof_processing_time: Histogram,

    /// Gauge for the highest committed l2 height
    #[metric(describe = "The highest committed l2 height")]
    pub highest_committed_l2_height: Gauge,

    /// Gauge for the highest committed l2 height
    #[metric(describe = "The highest committed l2 height")]
    pub highest_committed_index: Gauge,

    /// Gauge for the highest proven l2 height
    #[metric(describe = "The highest proven l2 height")]
    pub highest_proven_l2_height: Gauge,

    /// Histogram for the size of l2 blocks processed
    #[metric(describe = "The size of l2 blocks processed in bytes")]
    pub l2_block_size: Histogram,
}

impl FullnodeMetrics {
    /// Record for both gauge and histogram
    /// Gauge is used for per block exact time tracking, histogram is used for average and quantiles
    pub fn set_scan_l1_block_duration(&self, duration: f64) {
        self.scan_l1_block_duration_secs.set(duration);
        // also set histogram so we can follow average and quantiles properly
        histogram!("full_node_scan_l1_block_duration_secs_histogram").record(duration);
    }
}

/// Global instance of fullnode metrics
///
/// This static variable provides access to all fullnode metrics through a lazy-initialized
/// singleton pattern. The metrics are automatically described and initialized on first access.
pub static FULLNODE_METRICS: LazyLock<FullnodeMetrics> = LazyLock::new(|| {
    FullnodeMetrics::describe();
    FullnodeMetrics::default()
});
