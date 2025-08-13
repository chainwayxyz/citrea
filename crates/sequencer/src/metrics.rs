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
    /// Current number of transactions in the deposit data mempool
    #[metric(
        describe = "How many deposit data transactions are currently in the deposit data mempool"
    )]
    pub deposit_data_mempool_txs: Gauge,
    /// Counter for tracking deposit data mempool transaction increments
    #[metric(describe = "An ever increasing transactions count into the deposit data mempool")]
    pub deposit_data_mempool_txs_inc: Counter,
    /// Counter for tracking unaccepted deposit transactions
    #[metric(describe = "An ever increasing count of unaccepted deposit transactions")]
    pub unaccepted_deposit_txs: Counter,
    /// Histogram tracking the duration of deposit transaction eth_call
    #[metric(describe = "The duration of deposit transaction eth_call in seconds")]
    pub deposit_tx_call_duration: Histogram,
    /// Histogram tracking the size of deposit transactions
    #[metric(describe = "The size of deposit transactions in bytes")]
    pub deposit_tx_size: Histogram,
    /// Histogram tracking execution time of dry run operations
    #[metric(describe = "The duration of dry running transactions")]
    pub dry_run_execution: Histogram,
    /// Gauge tracking the exact time taken to dry run transactions, used for per block tracking
    #[metric(describe = "The exact time taken to dry run transactions in seconds")]
    pub dry_run_execution_gauge: Gauge,
    /// Histogram tracking the time taken to dry run a single transaction
    #[metric(describe = "The time taken to dry run a single transaction")]
    pub dry_run_single_tx_time: Histogram,
    /// Histogram tracking block production execution time
    #[metric(describe = "The duration of executing block transactions")]
    pub block_production_execution: Histogram,
    /// Gauge tracking the duration of the entire block production process, Gauge is used to track the exact time taken per block
    #[metric(describe = "The total duration of the entire block production process")]
    pub entire_block_production_duration_gauge: Gauge,
    /// Histogram tracking commitment sending execution time
    #[metric(describe = "The duration of sending a sequencer commitment")]
    pub send_commitment_execution: Histogram,
    /// Histogram tracking the entire process time of commitment
    #[metric(describe = "The total time taken to create a commitment and send it to DA")]
    pub commitment_entire_process_time: Histogram,
    /// Current count of blocks in the commitment
    #[metric(describe = "The number of blocks included in a sequencer commitment")]
    pub commitment_blocks_count: Gauge,
    /// Current commitment index being submitted to DA
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
    pub save_l2_block_time: Gauge,
    /// Histogram tracking the time taken to apply L2 block transactions
    #[metric(describe = "The time taken to apply transactions in an L2 block in milliseconds")]
    pub apply_l2_block_txs_time: Gauge,
    /// Histogram tracking the time taken to end an L2 block
    #[metric(describe = "The time taken to end an L2 block in milliseconds")]
    pub end_l2_block_time: Gauge,
    /// Histogram tracking the time taken to finalize an L2 block
    #[metric(describe = "The time taken to finalize an L2 block in milliseconds")]
    pub finalize_l2_block_time: Gauge,
    /// Histogram tracking the time taken to begin an L2 block
    #[metric(describe = "The time taken to begin an L2 block in milliseconds")]
    pub begin_l2_block_time: Gauge,
    /// Histogram tracking the time taken to encapsulate all evm txs in a sovereign call message, encoding it and signing it
    #[metric(
        describe = "The time taken to encapsulate all evm txs in a sovereign call message, encoding it and signing it in milliseconds"
    )]
    pub encode_and_sign_sov_tx_time: Gauge,
    /// Time taken to calculate the transaction merkle root
    #[metric(describe = "The time taken to calculate the transaction merkle root in seconds")]
    pub calculate_tx_merkle_root_time: Gauge,
    /// Histogram tracking the time taken to sign an L2 block header, including the time to calculate tx merkle root
    #[metric(
        describe = "The time taken to sign an L2 block header in milliseconds, including the time to calculate tx merkle root"
    )]
    pub sign_l2_block_header_time: Gauge,
    /// Histogram tracking the time taken to maintain the mempool after processing an L2 block
    #[metric(
        describe = "The time taken to maintain the mempool after processing an L2 block in milliseconds"
    )]
    pub maintain_mempool_time: Gauge,
    /// Basically all the operations happening before the dry run, such as fetching the mempool transactions, preparing the dry run state, etc.
    #[metric(describe = "The time taken to prepare for a dry run in seconds per block")]
    pub dry_run_preparation_time: Gauge,
    /// Gauge tracking exact time taken to dry run system transactions
    #[metric(describe = "The time taken to dry run system transactions in seconds")]
    pub dry_run_system_txs_duration_secs: Gauge,
    /// The exact time in seconds it took to produce an l2 block, without dry run
    #[metric(
        describe = "The exact time in seconds it took to produce an l2 block, without dry run"
    )]
    pub no_dry_run_block_production_duration_secs: Gauge,
    /// The l1 fee rate in the l2 block
    #[metric(describe = "The L1 fee rate in the l2 block")]
    pub l1_fee_rate: Gauge,
    /// The number of transactions that failed to pay the L1 fee in the current block
    #[metric(
        describe = "The number of transactions that failed to pay the L1 fee in the current block"
    )]
    pub l1_fee_failed_txs_count: Gauge,
    /// The number of transactions in the current L2 block
    #[metric(describe = "The number of transactions in the current L2 block")]
    pub l2_block_tx_count: Gauge,
    /// The time it took to process the latest sequencer commitment
    #[metric(describe = "The time in seconds it took to process the latest sequencer commitment")]
    pub latest_sequencer_commitment_process_duration_secs: Gauge,
    /// The index of the latest sequencer commitment
    #[metric(describe = "The index of the latest sequencer commitment")]
    pub latest_sequencer_commitment_index: Gauge,
    /// The l2 start height of the latest sequencer commitment
    #[metric(describe = "The l2 start height of the latest sequencer commitment")]
    pub latest_sequencer_commitment_l2_start_height: Gauge,
    /// The l2 end height of the latest sequencer commitment
    #[metric(describe = "The l2 end height of the latest sequencer commitment")]
    pub latest_sequencer_commitment_l2_end_height: Gauge,
    /// Histogram tracking seconds per l1 block processing in listen mode sequencer
    #[metric(describe = "The time in seconds it takes to process an L1 block in listen mode")]
    pub listen_mode_l1_block_process_duration_secs: Histogram,
    /// The size of the buffer for incoming transactions to be added in listen mode
    #[metric(
        describe = "The size of the buffer for incoming transactions to be added in listen mode"
    )]
    pub listen_mode_incoming_txs_to_be_added_buffer_size: Gauge,
    /// The size of the buffer for incoming transactions to be removed in listen mode
    #[metric(
        describe = "The size of the buffer for incoming transactions to be removed in listen mode"
    )]
    pub listen_mode_incoming_txs_to_be_removed_buffer_size: Gauge,
}

/// Sequencer metrics
pub static SEQUENCER_METRICS: LazyLock<SequencerMetrics> = LazyLock::new(|| {
    SequencerMetrics::describe();
    SequencerMetrics::default()
});
