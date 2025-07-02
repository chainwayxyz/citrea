use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;
use once_cell::sync::Lazy;

/// Defines the metrics being collected for the sequencer
#[derive(Metrics)]
#[metrics(scope = "sequencer")]
pub struct SequencerMetrics {
    /// Current number of transactions in the mempool
    #[metric(describe = "How many transactions are currently in the mempool")]
    pub mempool_txs: Gauge,
    /// Counter for tracking mempool transaction increments
    #[metric(describe = "An ever increasing transactions count into the mempool")]
    pub mempool_txs_inc: Counter,
    /// Histogram tracking execution time of dry run operations
    #[metric(describe = "The duration of dry running transactions")]
    pub dry_run_execution: Histogram,
    /// Histogram tracking block production execution time
    #[metric(describe = "The duration of executing block transactions")]
    pub block_production_execution: Histogram,
    /// Histogram tracking commitment sending execution time
    #[metric(describe = "The duration of sending a sequencer commitment")]
    pub send_commitment_execution: Histogram,
    /// Current count of blocks in the commitment
    #[metric(describe = "The number of blocks included in a sequencer commitment")]
    pub commitment_blocks_count: Gauge,
    /// Current L2 block number
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,
    /// Current L1 block number
    #[metric(describe = "The height of the current L1 block put into the Bitcoin Light Client")]
    pub current_l1_block: Gauge,
}

/// Sequencer metrics
pub static SEQUENCER_METRICS: Lazy<SequencerMetrics> = Lazy::new(|| {
    SequencerMetrics::describe();
    SequencerMetrics::default()
});
