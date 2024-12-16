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
    #[metric(describe = "The duration of processing a single soft confirmation")]
    pub process_soft_confirmation: Histogram,
}

/// Batch prover metrics
pub static BATCH_PROVER_METRICS: Lazy<BatchProverMetrics> = Lazy::new(|| {
    BatchProverMetrics::describe();
    BatchProverMetrics::default()
});
