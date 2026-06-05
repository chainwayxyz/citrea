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
//!     Normally producer sequencer stores all the mempool transactions in persistent storage as well to recover them in case of crashes and restarts
//!     For that reason listen mode sequencer also stores all mempool transactions in its own persistent storage, updates the persistent storage regularly and does not keep in block txs in that storage
//!     When restarted as producer sequencer, it will put all the txs in the persistent storage back into mempool
use std::sync::Arc;
use std::time::Duration;

use citrea_common::l2::{AppliedL2Block, L2BlockProcessor, L2Syncer};
use citrea_common::{read_init_params_from_db, RollupPublicKeys, SequencerConfig};
use citrea_primitives::forks::get_forks;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use l1_syncer::L1Syncer;
use mempool_syncer::MempoolSyncer;
use parking_lot::Mutex;
use reth_provider::CanonStateNotification;
use reth_tasks::shutdown::GracefulShutdown;
use reth_tasks::{TaskExecutor, TaskManager};
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps, SharedLedgerOps};
use sov_db::schema::types::L2BlockNumber;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::MempoolTransactionSignal;
use sov_rollup_interface::services::da::DaService;
use tokio::runtime::Handle;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{info, warn};

use super::metrics::SEQUENCER_METRICS as SM;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::types::SequencerRpcMessage;
use crate::CitreaSequencer;

/// Maximum time to wait for the listen-mode syncers to stop before a listen->producer conversion
/// proceeds anyway. Bounds the conversion so a misbehaving syncer can never hang it indefinitely.
const SYNCER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Module for syncing and storing sequencer commitments extracted from L1 blocks.
pub(crate) mod l1_syncer;
/// Module containing mempool synchronization functionality for listen mode sequencer
pub(crate) mod mempool_syncer;

/// Listen Mode Sequencer L2 Syncer
pub type ListenModeSequencerL2Syncer<DA, DB> =
    L2Syncer<DA, DB, ListenModeSequencerL2BlockProcessor>;

/// Listen Mode Sequencer L2 block processor
pub struct ListenModeSequencerL2BlockProcessor;

impl<DB> L2BlockProcessor<DB> for ListenModeSequencerL2BlockProcessor
where
    DB: sov_db::ledger_db::SequencerLedgerOps,
{
    fn process_result(result: &AppliedL2Block, db: &DB) -> anyhow::Result<()> {
        db.set_state_diff(L2BlockNumber(result.l2_height), &result.state_diff.clone())
    }

    fn record_metrics(l2_height: u64, _block_size: usize, process_block_duration_secs: f64) {
        SM.current_l2_block.set(l2_height as f64);
        SM.entire_block_production_duration_gauge
            .set(process_block_duration_secs);
    }
}

/// Everything needed to build a block-producing [`CitreaSequencer`] when a listen-mode sequencer is
/// promoted to producer at runtime.
///
/// The listen-mode syncers consume the original `init_params`, `StfBlueprint` and `ForkManager`, so
/// those are re-derived at conversion time (see [`build_producer`]). This struct holds the rest of
/// the handles — all cheaply cloneable or single-owner — so that no process restart is required to
/// start producing blocks.
pub struct ProducerParts<Da: DaService> {
    /// Data availability service.
    pub da_service: Arc<Da>,
    /// Producer sequencer configuration (with `listen_mode_config` cleared).
    pub config: SequencerConfig,
    /// Rollup public keys.
    pub public_keys: RollupPublicKeys,
    /// Prover storage manager (shares the same backing DBs as the syncers).
    pub storage_manager: ProverStorageManager,
    /// Ledger database.
    pub ledger_db: LedgerDB,
    /// Database provider used by the mempool.
    pub db_provider: DbProvider,
    /// Transaction mempool (shared with the RPC layer).
    pub mempool: Arc<CitreaMempool>,
    /// Deposit transaction mempool.
    pub deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    /// Broadcast sender for L2 block notifications.
    pub l2_block_tx: broadcast::Sender<u64>,
    /// Broadcast sender for mempool transaction notifications.
    pub mempool_transaction_tx: broadcast::Sender<MempoolTransactionSignal>,
    /// Backup manager.
    pub backup_manager: Arc<citrea_common::backup::BackupManager>,
    /// Receiver for RPC control messages. Used by the orchestrator to receive the convert signal,
    /// then handed to the producer to receive halt/resume/test-block messages.
    pub rpc_message_rx: UnboundedReceiver<SequencerRpcMessage>,
    /// Canonical state notification sender for mempool maintenance.
    pub canon_state_tx: UnboundedSender<CanonStateNotification>,
    /// Task executor used by the producer to spawn its background tasks.
    pub task_executor: TaskExecutor,
}

/// Builds a block-producing [`CitreaSequencer`] from [`ProducerParts`], re-deriving the pieces that
/// were consumed by the listen-mode syncers (`InitParams` read back from the DB, a fresh
/// `StfBlueprint`, and a fresh `ForkManager` at the current head height).
///
/// The caller MUST have stopped the listen-mode syncers and awaited their completion before calling
/// this, so the head state read here is final and there is only ever a single writer to the ledger.
fn build_producer<Da: DaService>(parts: ProducerParts<Da>) -> anyhow::Result<CitreaSequencer<Da>> {
    let current_l2_height = parts
        .ledger_db
        .get_head_l2_block()?
        .map(|(l2_height, _)| l2_height.0)
        .unwrap_or(0);

    let mut fork_manager = ForkManager::new(get_forks(), current_l2_height);
    fork_manager.register_handler(Box::new(parts.ledger_db.clone()));

    let native_stf =
        StfBlueprint::<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>::new();
    let init_params = read_init_params_from_db(&parts.ledger_db, &parts.storage_manager)?;

    CitreaSequencer::new(
        parts.da_service,
        parts.config,
        init_params,
        native_stf,
        parts.storage_manager,
        parts.public_keys,
        parts.ledger_db,
        parts.db_provider,
        parts.mempool,
        parts.deposit_mempool,
        fork_manager,
        parts.l2_block_tx,
        parts.mempool_transaction_tx,
        parts.backup_manager,
        parts.rpc_message_rx,
        parts.canon_state_tx,
        parts.task_executor,
    )
}

/// Listen Mode Sequencer that synchronizes both L1 and L2 blocks and commitments
/// This struct encapsulates the L1 and L2 block synchronization services
/// and provides a run loop for processing incoming L1 and L2 blocks and commitments.
/// It is designed to maintain the sequencer's state in listen mode.
///
/// In addition to staying in sync, it can be promoted to a block-producing sequencer at runtime via
/// the `citrea_convertToProducer` RPC (see [`ProducerParts`] and [`build_producer`]). On promotion
/// it stops its syncers and starts producing blocks from the state it has already synced, without a
/// process restart.
///
/// # Type Parameters
/// * `DA` - Data Availability service type
/// * `DB` - Database type that implements `SequencerLedgerOps` for ledger operations
pub struct ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// L2 block synchronization service for the listen mode sequencer
    pub l2_syncer: ListenModeSequencerL2Syncer<DA, DB>,
    /// L1 block synchronization service for the listen mode sequencer
    pub l1_syncer: L1Syncer<DA, DB>,
    /// Mempool synchronization service for the listen mode sequencer
    pub mempool_syncer: MempoolSyncer<DB>,
    /// Database for ledger operations
    pub ledger_db: DB,
    /// Handles required to build a producer sequencer on conversion.
    pub producer_parts: ProducerParts<DA>,
}

impl<DA, DB> ListenModeSequencer<DA, DB>
where
    DA: DaService,
    DB: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new Listen Mode Sequencer instance
    ///
    /// # Arguments
    /// * `l2_syncer` - L2 block synchronization service
    /// * `l1_syncer` - L1 block synchronization service
    /// * `mempool_syncer` - Mempool synchronization service
    /// * `ledger_db` - Database for ledger operations
    /// * `producer_parts` - Handles needed to build a producer sequencer on conversion
    pub fn new(
        l2_syncer: ListenModeSequencerL2Syncer<DA, DB>,
        l1_syncer: L1Syncer<DA, DB>,
        mempool_syncer: MempoolSyncer<DB>,
        ledger_db: DB,
        producer_parts: ProducerParts<DA>,
    ) -> Self {
        Self {
            l2_syncer,
            l1_syncer,
            mempool_syncer,
            ledger_db,
            producer_parts,
        }
    }

    /// Main Listen Mode Sequencer run loop.
    ///
    /// Spawns the L2/L1/mempool syncers under a dedicated [`TaskManager`] so they can be stopped
    /// independently of the process shutdown, then waits for either:
    /// - the process `shutdown_signal`, in which case it stops the syncers and returns, or
    /// - a [`SequencerRpcMessage::ConvertToProducer`] signal, in which case it stops the syncers,
    ///   builds a producer sequencer from the synced state, and hands off to its run loop.
    ///
    /// # Arguments
    /// * `shutdown_signal` - Signal for graceful shutdown of the whole node
    pub async fn run(self, mut shutdown_signal: GracefulShutdown) -> Result<(), anyhow::Error> {
        let ListenModeSequencer {
            l2_syncer,
            l1_syncer,
            mempool_syncer,
            ledger_db,
            mut producer_parts,
        } = self;

        // Dedicated task manager so the syncers can be shut down independently of the node, which is
        // required to release the ledger as the single writer before the producer starts.
        let syncer_manager = TaskManager::new(Handle::current());
        let syncer_executor = syncer_manager.executor();

        // Start L2 syncer task
        syncer_executor.spawn_critical_with_graceful_shutdown_signal(
            "listen_mode_sequencer_l2_syncer",
            |shutdown_signal| async move { l2_syncer.run(shutdown_signal).await },
        );

        // Start mempool syncer task
        syncer_executor.spawn_with_graceful_shutdown_signal(|shutdown_signal| async move {
            mempool_syncer.run(shutdown_signal).await
        });

        // Start L1 syncer task once at least one L2 block has been processed.
        {
            let ledger_db = ledger_db.clone();
            syncer_executor.spawn_critical_with_graceful_shutdown_signal(
                "listen_mode_sequencer_l1_syncer",
                |shutdown_signal| async move {
                    while ledger_db
                        .get_head_l2_block_height()
                        .ok()
                        .flatten()
                        .unwrap_or(0)
                        < 1
                    {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    l1_syncer.run(shutdown_signal).await
                },
            );
        }

        let mut syncer_manager = Some(syncer_manager);
        let mut control_closed = false;
        loop {
            tokio::select! {
                _ = &mut shutdown_signal => {
                    info!("Shutting down listen mode sequencer");
                    if let Some(manager) = syncer_manager.take() {
                        let _ = tokio::task::spawn_blocking(move || {
                            manager.graceful_shutdown_with_timeout(SYNCER_SHUTDOWN_TIMEOUT)
                        })
                        .await;
                    }
                    return Ok(());
                }
                msg = producer_parts.rpc_message_rx.recv(), if !control_closed => {
                    match msg {
                        Some(SequencerRpcMessage::ConvertToProducer { ack }) => {
                            info!("Listen mode sequencer: received convert-to-producer signal");

                            // Stop the syncers and wait for them to fully drain so the producer
                            // starts from the final head state with no competing writer. Bounded by
                            // a timeout so a syncer that fails to stop can never hang the conversion.
                            if let Some(manager) = syncer_manager.take() {
                                match tokio::task::spawn_blocking(move || {
                                    manager.graceful_shutdown_with_timeout(SYNCER_SHUTDOWN_TIMEOUT)
                                })
                                .await
                                {
                                    Ok(true) => {}
                                    Ok(false) => warn!(
                                        "Listen mode sequencer: syncers did not stop within timeout; \
                                         proceeding with conversion"
                                    ),
                                    Err(e) => {
                                        let msg = format!("failed to stop listen-mode syncers: {e}");
                                        let _ = ack.send(Err(msg.clone()));
                                        return Err(anyhow::anyhow!(msg));
                                    }
                                }
                            }

                            match build_producer(producer_parts) {
                                Ok(mut producer) => {
                                    let _ = ack.send(Ok(()));
                                    info!("Listen mode sequencer: converted to producer, starting block production");
                                    return producer.run(shutdown_signal).await;
                                }
                                Err(e) => {
                                    let _ = ack.send(Err(format!("failed to build producer: {e}")));
                                    return Err(e);
                                }
                            }
                        }
                        Some(_) => {
                            // Other RPC control messages (halt/resume/test block) are not
                            // applicable while in listen mode; ignore them.
                            warn!("Listen mode sequencer: ignoring unsupported RPC control message");
                        }
                        None => {
                            warn!("Listen mode sequencer: RPC control channel closed");
                            control_closed = true;
                        }
                    }
                }
            }
        }
    }
}
