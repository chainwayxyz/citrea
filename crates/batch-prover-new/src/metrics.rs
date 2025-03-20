use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

#[derive(Metrics)]
#[metrics(scope = "batch_prover")]
pub struct BatchProverMetrics {
    #[metric(describe = "The current L1 block number which is used to produce L2 blocks")]
    pub current_l1_block: Gauge,
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,
    #[metric(describe = "The duration of processing a single l2 block")]
    pub process_l2_block: Histogram,
    #[metric(describe = "The duration of scanning and processing a single L1 block")]
    pub scan_l1_block: Histogram,
}

/// Batch prover metrics
pub static BATCH_PROVER_METRICS: Lazy<BatchProverMetrics> = Lazy::new(|| {
    BatchProverMetrics::describe();
    BatchProverMetrics::default()
});
