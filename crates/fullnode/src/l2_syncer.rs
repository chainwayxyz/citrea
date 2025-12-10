//! L2 block synchronization for the fullnode
//!
//! This module contains functionality for synchronizing L2 blocks from the sequencer
//! and processing them to maintain the fullnode's state.

use citrea_common::l2::{AppliedL2Block, L2BlockProcessor, L2Syncer};

use crate::metrics::FULLNODE_METRICS;

pub type FullNodeL2Syncer<DA, DB> = L2Syncer<DA, DB, FullNodeL2BlockProcessor>;

/// Full node L2 block processor
pub struct FullNodeL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for FullNodeL2BlockProcessor {
    fn process_result(_result: &AppliedL2Block, _db: &DB) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_metrics(l2_height: u64, block_size: usize, block_process_duration_secs: f64) {
        FULLNODE_METRICS.current_l2_block.set(l2_height as f64);
        FULLNODE_METRICS
            .process_l2_block
            .record(block_process_duration_secs);
        FULLNODE_METRICS.l2_block_size.record(block_size as f64);
    }
}
