//! L2 block synchronization for the batch prover
//!
//! This module contains functionality for synchronizing L2 blocks from the sequencer
//! and processing them to maintain the batch prover's state.

use citrea_common::l2::{AppliedL2Block, L2BlockProcessor, L2Syncer};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;

use crate::metrics::BATCH_PROVER_METRICS;

pub type BatchProverL2Syncer<DA, DB> = L2Syncer<DA, DB, BatchProverL2BlockProcessor>;

/// Batch prover L2 block processor
pub struct BatchProverL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for BatchProverL2BlockProcessor
where
    DB: BatchProverLedgerOps,
{
    fn process_result(result: &AppliedL2Block, db: &DB) -> anyhow::Result<()> {
        db.set_l2_state_diff(L2BlockNumber(result.l2_height), result.state_diff.clone())
    }

    fn record_metrics(l2_height: u64, _block_size: usize, block_process_duration_secs: f64) {
        BATCH_PROVER_METRICS.current_l2_block.set(l2_height as f64);
        BATCH_PROVER_METRICS
            .process_l2_block
            .record(block_process_duration_secs);
    }
}
