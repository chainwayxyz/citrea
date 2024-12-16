use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

#[derive(Metrics)]
#[metrics(scope = "fullnode")]
pub struct FullnodeMetrics {
    #[metric(describe = "The current L1 block number which is used to produce L2 blocks")]
    pub current_l1_block: Gauge,
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block: Histogram,
    #[metric(describe = "The duration of processing a single soft confirmation")]
    pub process_soft_confirmation: Histogram,
}

/// Fullnode metrics
pub static FULLNODE_METRICS: Lazy<FullnodeMetrics> = Lazy::new(|| {
    FullnodeMetrics::describe();
    FullnodeMetrics::default()
});
