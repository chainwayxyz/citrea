use std::sync::LazyLock;

use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;

/// Defines the metrics being collected for the sequencer
#[allow(unused)]
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
    /// Histogram tracking the entire process time of commitment
    #[metric(describe = "The total time taken to create a commitment and send it to DA")]
    pub commitment_entire_process_time: Histogram,
    /// Current count of blocks in the commitment
    #[metric(describe = "The number of blocks included in a sequencer commitment")]
    pub commitment_blocks_count: Gauge,
    /// Current commitment indext being submitted to DA
    #[metric(describe = "The index of commitment that is being submitted to DA")]
    pub currently_committing_index: Gauge,
    /// Current L2 block number
    #[metric(describe = "The current L2 block number")]
    pub current_l2_block: Gauge,
    /// Current L1 block number
    #[metric(describe = "The height of the current L1 block put into the Bitcoin Light Client")]
    pub current_l1_block: Gauge,
    /// The number of transactions that are dry run in the current block
    #[metric(
        describe = "The time in milliseconds it took to run transactions in the current block, this does not include the time to dry run the transactions"
    )]
    pub block_production_time: Histogram,
    /// Histogram tracking the time taken for dry run a transaction
    #[metric(
        describe = "The time taken to dry run a transaction in the current block in milliseconds"
    )]
    pub dry_run_tx_time: Histogram,

    /// Histogram tracking the time taken to save an L2 block
    #[metric(describe = "The time taken to save an L2 block in milliseconds")]
    pub save_l2_block_time: Histogram,

    /// Histogram tracking the time taken to apply L2 block transactions
    #[metric(describe = "The time taken to apply transactions in an L2 block in milliseconds")]
    pub apply_l2_block_txs_time: Histogram,

    /// Histogram tracking the time taken to end an L2 block
    #[metric(describe = "The time taken to end an L2 block in milliseconds")]
    pub end_l2_block_time: Histogram,

    /// Histogram tracking the time taken to finalize an L2 block
    #[metric(describe = "The time taken to finalize an L2 block in milliseconds")]
    pub finalize_l2_block_time: Histogram,

    /// Histogram tracking the time taken to begin an L2 block
    #[metric(describe = "The time taken to begin an L2 block in milliseconds")]
    pub begin_l2_block_time: Histogram,

    /// Histogram tracking the time taken to encapsulate all evm txs in a sovereign call message, encoding it and signing it
    #[metric(
        describe = "The time taken to encapsulate all evm txs in a sovereign call message, encoding it and signing it in milliseconds"
    )]
    pub encode_and_sign_sov_tx_time: Histogram,

    /// Histogram tracking the time taken to sign an L2 block header, including the time to calculate tx merkle root
    #[metric(
        describe = "The time taken to sign an L2 block header in milliseconds, including the time to calculate tx merkle root"
    )]
    pub sign_l2_block_header_time: Histogram,

    /// Histogram tracking the time taken to maintain the mempool after processing an L2 block
    #[metric(
        describe = "The time taken to maintain the mempool after processing an L2 block in milliseconds"
    )]
    pub maintain_mempool_time: Histogram,

    /// Histogram tracking the time taken to prepare for a dry run
    #[metric(describe = "The time taken to prepare for a dry run in milliseconds")]
    pub dry_run_preparation_time: Histogram,

    /// Histogram tracking the time taken to dry run system transactions
    #[metric(describe = "The time taken to dry run system transactions in milliseconds")]
    pub dry_run_system_txs_time: Histogram,

    /// The l1 fee rate in the l2 block
    #[metric(describe = "The L1 fee rate in the l2 block")]
    pub l1_fee_rate: Gauge,
}

/// Sequencer metrics
pub static SEQUENCER_METRICS: LazyLock<SequencerMetrics> = LazyLock::new(|| {
    SequencerMetrics::describe();
    SequencerMetrics::default()
});
