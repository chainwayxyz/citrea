//! L2 block synchronization for the listen mode sequencer
//!
//! This module contains functionality for synchronizing L2 blocks and commitments from the sequencer
//! and processing them to maintain the listen mode sequencer's state to be the same with sequencer's state.

use citrea_common::l2::{L2BlockProcessor, L2Syncer, ProcessL2BlockResult};
use reth_tasks::TaskExecutor;
use sov_rollup_interface::services::da::DaService;

use crate::l1_syncer::L1Syncer;

/// Listen Mode Sequencer L2 Syncer
pub type ListenModeSequencerL2Syncer<DA, DB> =
    L2Syncer<DA, DB, ListenModeSequencerL2BlockProcessor>;

/// Listen Mode Sequencer L2 block processor
pub struct ListenModeSequencerL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for ListenModeSequencerL2BlockProcessor
where
    DB: sov_db::ledger_db::SequencerLedgerOps,
{
    fn process_result(_result: &ProcessL2BlockResult, _db: &DB) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_metrics(_result: &ProcessL2BlockResult) {
        // Metrics recording logic can be added here if needed
    }
}

/// Listen Mode Sequencer that synchronizes both L1 and L2 blocks and commitments
/// This struct encapsulates the L1 and L2 block synchronization services
/// and provides a run loop for processing incoming L1 and L2 blocks and commitments.
/// It is designed to maintain the sequencer's state in listen mode.
///
/// # Type Parameters
/// * `DA` - Data Availability service type
/// * `DB` - Database type that implements `SequencerLedgerOps` for ledger operations
pub struct ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: sov_db::ledger_db::SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// L2 block synchronization service for the listen mode sequencer
    pub l2_syncer: ListenModeSequencerL2Syncer<DA, DB>,
    /// L1 block synchronization service for the listen mode sequencer
    pub l1_syncer: L1Syncer<DA, DB>,
    /// Task executor for running asynchronous tasks
    pub task_executor: TaskExecutor,
}

impl<DA, DB> ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: sov_db::ledger_db::SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new Listen Mode Sequencer instance
    ///
    /// # Arguments
    /// * `l2_syncer` - L2 block synchronization service
    /// * `l1_syncer` - L1 block synchronization service
    /// * `task_executor` - Task executor for running asynchronous tasks
    pub fn new(
        l2_syncer: ListenModeSequencerL2Syncer<DA, DB>,
        l1_syncer: L1Syncer<DA, DB>,
        task_executor: TaskExecutor,
    ) -> Self {
        Self {
            l2_syncer,
            l1_syncer,
            task_executor,
        }
    }

    /// Main Listen Mode Sequencer run loop
    ///
    /// # Arguments
    /// * `shutdown_signal` - Signal for graceful shutdown
    pub async fn run(self) -> Result<(), anyhow::Error> {
        // Start L2 syncer task
        self.task_executor
            .spawn_critical_with_graceful_shutdown_signal(
                "listen_mode_sequencer_l2_syncer",
                |shutdown_signal| async move { self.l2_syncer.run(shutdown_signal).await },
            );

        // Start L1 syncer task
        self.task_executor
            .spawn_critical_with_graceful_shutdown_signal(
                "listen_mode_sequencer_l1_syncer",
                |shutdown_signal| async move { self.l1_syncer.run(shutdown_signal).await },
            );

        Ok(())
    }
}
