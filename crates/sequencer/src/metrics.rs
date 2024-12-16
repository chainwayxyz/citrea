use metrics::{Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

#[derive(Metrics)]
#[metrics(scope = "sequencer")]
pub struct SequencerMetrics {
    #[metric(describe = "How many transactions are currently in the mempool")]
    pub mempool_txs: Gauge,
    #[metric(describe = "The duration of dry running transactions")]
    pub dry_run_execution: Histogram,
    #[metric(describe = "The duration of executing block transactions")]
    pub block_production_execution: Histogram,
    #[metric(describe = "The duration of sending a sequencer commitment")]
    pub send_commitment_execution: Histogram,
    #[metric(describe = "The number of blocks included in a sequencer commitment")]
    pub commitment_blocks_count: Gauge,
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,
    #[metric(describe = "The current L1 block number which is used to produce L2 blocks")]
    pub current_l1_block: Gauge,
}

/// Sequencer metrics
pub static SEQUENCER_METRICS: Lazy<SequencerMetrics> = Lazy::new(|| {
    SequencerMetrics::describe();
    SequencerMetrics::default()
});
