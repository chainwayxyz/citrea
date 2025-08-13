//! This module contains the sequencers listen mode functionality
//!
//! Listen mode sequencer lives as a separate process in the same network with sequencer and its purpose is to be a backup of the producer sequencer.
//! It stores almost everything in the ledger db and state the same way sequencer does.
//! In case of sequencer failure the listen mode sequencer will be restarted with sequencer config, since it has the same state with the  producer sequencer it will continue from where the crashed sequencer has left off.
//! This is useful in scenarios like:
//! - Sequencer node running out of memory and crashing
//! - Sequencer node running out of disk space and crashing
//!
//! This node will provide us high availability and fault tolerance.
//!
//! Listen Mode sequencer is not a new type of node, it is a different way to start sequencer which does not produce block or submit commitments, rather connects to the producer sequencer and bitcoin and listens for:
//! - New L2 Blocks:
//!     This is done via both polling and subscription. Since subscription (websocket) will only provide the latest blocks and is prone to losses we also use polling to ensure we don't miss any blocks.
//!     Uses the common **L2 Syncer** module
//! - L1 block synchronization for sequencer commitments:
//!     Listen mode sequencer scans finalized L1 blocks starting from the first l2 blocks recorded l1 height on bitcoin light client contract
//!     This is for saving the sequencer commitments and when restarted as producer sequencer it will only fetch commitments that are non-finalized or in mempool using `resubmit_pending_commitments` function
//!     Listen mode sequencer does not need to track pending commitments of producer sequencer because the commitment service is deterministic and readonly sequencer will be creating the same exact commitments
//! - Mempool transactions:
//!     Normally producer sequencer stores all the mempool transactions in persisten storage as well to recover them in case of crashes and restarts
//!     For that reason listen mode sequencer also stores all mempool transactions in its own persistent storage, updates the persisten storage regularly and does not keep in block txs in that storage
//!     When restarted as producer sequencer, it will put all the txs in the persistent storage back into mempool

use citrea_common::l2::{L2BlockProcessor, L2Syncer, ProcessL2BlockResult};
use reth_tasks::TaskExecutor;
use sov_db::schema::types::L2BlockNumber;
use sov_rollup_interface::services::da::DaService;

use crate::l1_syncer::L1Syncer;
use crate::mempool_syncer::MempoolSyncer;
use crate::metrics::SEQUENCER_METRICS as SM;

/// Listen Mode Sequencer L2 Syncer
pub type ListenModeSequencerL2Syncer<DA, DB> =
    L2Syncer<DA, DB, ListenModeSequencerL2BlockProcessor>;

/// Listen Mode Sequencer L2 block processor
pub struct ListenModeSequencerL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for ListenModeSequencerL2BlockProcessor
where
    DB: sov_db::ledger_db::SequencerLedgerOps,
{
    fn process_result(result: &ProcessL2BlockResult, db: &DB) -> anyhow::Result<()> {
        db.set_state_diff(L2BlockNumber(result.l2_height), &result.state_diff.clone())
    }

    fn record_metrics(result: &ProcessL2BlockResult) {
        SM.current_l2_block.set(result.l2_height as f64);
        SM.entire_block_production_duration_gauge
            .set(result.process_duration);
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
    /// Mempool synchronization service for the listen mode sequencer
    pub mempool_syncer: MempoolSyncer<DB>,
    /// Task executor for running asynchronous tasks
    pub task_executor: TaskExecutor,
    /// Database for ledger operations
    pub ledger_db: DB,
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
        mempool_syncer: MempoolSyncer<DB>,
        task_executor: TaskExecutor,
        ledger_db: DB,
    ) -> Self {
        Self {
            l2_syncer,
            l1_syncer,
            mempool_syncer,
            task_executor,
            ledger_db,
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

        while self.ledger_db.get_head_l2_block_height()?.unwrap_or(0) < 1 {
            // Wait until one block to be processed before starting L1 syncer
        }

        // Start L1 syncer task
        self.task_executor
            .spawn_critical_with_graceful_shutdown_signal(
                "listen_mode_sequencer_l1_syncer",
                |shutdown_signal| async move { self.l1_syncer.run(shutdown_signal).await },
            );

        self.task_executor
            .spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
                self.mempool_syncer.run(shutdown_signal).await
            });

        Ok(())
    }
}
