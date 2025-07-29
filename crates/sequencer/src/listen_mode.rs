//! L2 block synchronization for the listen mode sequencer
//!
//! This module contains functionality for synchronizing L2 blocks and commitments from the sequencer
//! and processing them to maintain the listen mode sequencer's state to be the same with sequencer's state.

use alloy_network::any;
use anyhow::Error;
use citrea_common::l2::{L2BlockProcessor, L2Syncer, ProcessL2BlockResult};
use reth_tasks::shutdown::GracefulShutdown;
use sov_rollup_interface::services::da::DaService;

pub type ListenModeSequencerL2Syncer<DA, DB> =
    L2Syncer<DA, DB, ListenModeSequencerL2BlockProcessor>;

pub struct ListenModeSequencerL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for ListenModeSequencerL2BlockProcessor
where
    DB: sov_db::ledger_db::SequencerLedgerOps,
{
    fn process_result(result: &ProcessL2BlockResult, db: &DB) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_metrics(result: &ProcessL2BlockResult) {
        // Metrics recording logic can be added here if needed
    }
}

pub struct ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: sov_db::ledger_db::SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    pub l2_syncer: ListenModeSequencerL2Syncer<DA, DB>,
}

impl<DA, DB> ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: sov_db::ledger_db::SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(l2_syncer: ListenModeSequencerL2Syncer<DA, DB>) -> Self {
        Self { l2_syncer }
    }

    pub async fn run(
        &mut self,
        mut shutdown_signal: GracefulShutdown,
    ) -> Result<(), anyhow::Error> {
        // Run the L2 syncer
        Ok(())
    }
}
