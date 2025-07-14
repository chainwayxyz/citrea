#![warn(clippy::missing_docs_in_private_items)]
//! This crate contains the batch prover constructs.
//!
//! There are 3 main components:
//!
//! 1. L1 syncer: responsible from tracking the finalized L1 blocks and extracting the sequencer commitments from them.
//! 2. L2 syncer: responsible from tracking the L2 blocks by syncing them from the sequencer.
//! 3. Prover: responsible from handling the proving process. It tracks the pending commitments and
//!    tries to partition them into provable chunks.
//!
//! L1 syncer sends signals to the Prover when it finds new L1 blocks in the L1 chain.
//! L2 syncer sends signals to the Prover when it finds new L2 blocks in the L2 chain. This is needed when Prover is blocked on proving commitments due to unsynced L2 chain.
//! RPC module also sends direct requests to the Prover to pause, or prove a new commitment.
//!
//! Prover handles these signals as following:
//! - Checks sampling to decide whether it should continue with proving
//! - Checks if there are any pending commitments to prove
//! - Filters out commitments that are not yet synced to the L2 chain
//! - Filters out commitments that have an unknown previous commitment, e.g. 1 is unknown [2, 3] is pending -> 2 is filtered out and 3 is provable
//! - Partitions the commitments into provable chunks based on the following criteria:
//!     - Index gap
//!     - State diff threshold
//!     - Spec change
//! - Starts proving job for each partition
//! - Spawns a task to watch the proving jobs to finish in the background
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::{BatchProverConfig, InitParams, RollupPublicKeys, RunnerConfig};
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::RpcModule;
pub use l1_syncer::L1Syncer;
pub use l2_syncer::L2Syncer;
pub use partition::PartitionMode;
use prover::Prover;
use prover_services::ParallelProverService;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::fork::ForkManager;
use sov_modules_api::{SpecId, Zkvm};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::{broadcast, mpsc, Mutex};

/// Module containing database migration definitions
pub mod db_migrations;
/// Module for syncing and storing L1 blocks and relevant DA data
pub mod l1_syncer;
/// Module for L2 block synchronization
mod l2_syncer;
/// Module for metrics collection
mod metrics;
/// Module that contains functionality for partitioning commitments into provable chunks
mod partition;
/// Prover module that handles the proving process using the partitioning module to create provable chunks
pub mod prover;
/// Module providing RPC functionality
pub mod rpc;

/// Setup function to build all the services required to run a batch prover.
/// Sets up the L1 and L2 syncers, the prover, and the RPC module.
/// Builds and initializes all batch prover services.
///
/// # Arguments
/// * `prover_config` - Configuration for the batch prover.
/// * `runner_config` - Runner configuration for the batch prover.
/// * `init_params` - Initialization parameters for the batch prover start up.
/// * `native_stf` - State transition function blueprint for the batch prover.
/// * `public_keys` - Rollup public keys containing the sequencer's and batch prover's keys for cryptographic operations.
/// * `da_service` - Data availability service implementation.
/// * `prover_service` - Prover service implementation for parallel proving.
/// * `ledger_db` - Database for ledger operations.
/// * `storage_manager` - Manager for prover storage.
/// * `l2_block_tx` - Channel for L2 block notifications.
/// * `fork_manager` - Manager for handling chain forks.
/// * `code_commitments` - Map of ZKVM code commitments by spec ID.
/// * `elfs` - Map of ZKVM ELF binaries by spec ID.
/// * `rpc_module` - RPC module for external communication.
/// * `backup_manager` - Manager for backup operations.
///
/// # Type Parameters
/// * `DA` - Data availability service type.
/// * `DB` - Database type implementing `BatchProverLedgerOps`.
/// * `Vm` - ZKVM implementation type.
///
/// # Returns
/// A tuple containing:
/// - `L2Syncer` for block synchronization.
/// - `L1Syncer` for DA block processing.
/// - `Prover` for handling the proving process.
/// - `RpcModule` configured with the necessary RPC methods.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub async fn build_services<DA, DB, Vm>(
    prover_config: BatchProverConfig,
    runner_config: RunnerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<
        DefaultContext,
        <DA as DaService>::Spec,
        CitreaRuntime<DefaultContext, <DA as DaService>::Spec>,
    >,
    public_keys: RollupPublicKeys,
    da_service: Arc<DA>,
    prover_service: Arc<ParallelProverService<DA, Vm>>,
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    l2_block_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    code_commitments: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
    elfs: HashMap<SpecId, Vec<u8>>,
    rpc_module: RpcModule<()>,
    backup_manager: Arc<BackupManager>,
) -> Result<(
    L2Syncer<DA, DB>,
    L1Syncer<DA, DB>,
    Prover<DA, DB, Vm>,
    RpcModule<()>,
)>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    let l1_block_cache = Arc::new(Mutex::new(L1BlockCache::new()));
    let (request_tx, request_rx) = mpsc::channel(4);

    let rpc_context = rpc::create_rpc_context::<_, _, Vm>(
        ledger_db.clone(),
        request_tx,
        da_service.clone(),
        storage_manager.clone(),
        code_commitments.clone(),
    );
    let rpc_module = rpc::register_rpc_methods(rpc_context, rpc_module)?;

    let l2_syncer = L2Syncer::new(
        runner_config.clone(),
        init_params,
        native_stf,
        public_keys.clone(),
        da_service.clone(),
        ledger_db.clone(),
        storage_manager.clone(),
        fork_manager,
        l2_block_tx.clone(),
        backup_manager.clone(),
        true,
    )?;

    let (l1_signal_tx, l1_signal_rx) = mpsc::channel(1);

    let l1_syncer = L1Syncer::new(
        ledger_db.clone(),
        da_service,
        public_keys.clone(),
        runner_config.scan_l1_start_height,
        l1_block_cache,
        backup_manager,
        l1_signal_tx,
    );

    let l2_block_rx = l2_block_tx.subscribe();

    let prover = Prover::new(
        prover_config,
        ledger_db,
        storage_manager,
        prover_service,
        public_keys.sequencer_public_key,
        elfs,
        code_commitments,
        l1_signal_rx,
        l2_block_rx,
        request_rx,
    );

    Ok((l2_syncer, l1_syncer, prover, rpc_module))
}
