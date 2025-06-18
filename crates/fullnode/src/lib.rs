#![warn(clippy::missing_docs_in_private_items)]
//! Fullnode implementation for the Citrea rollup
//!
//! This crate provides functionality for running a full node in the Citrea network.
//! A full node is responsible for:
//! - Syncing and validating L2 blocks
//! - Processing L1 blocks in order to track finality of the rollup.
//! - Managing state and storage
//! - Providing RPC services
//! - Optional pruning of historical data
//!
//! # L2 Block Processing
//!
//! The fullnode processes L2 blocks through a coordinated system involving several components,
//! primarily the `L2Syncer` and `L1BlockHandler`. The process ensures proper synchronization,
//! validation, and state transitions of L2 blocks while maintaining consistency with L1 blocks.
//!
//! ## Main Components
//!
//! ### 1. L2Syncer
//! The `L2Syncer` is the primary component responsible for synchronizing and processing L2 blocks.
//! It maintains the state of the L2 chain by:
//! - Fetching new blocks from the sequencer
//! - Validating block signatures and contents
//! - Processing blocks to update the local state
//! - Managing forks and state transitions
//!
//! ### 2. L1BlockHandler
//! The `L1BlockHandler` processes L1 blocks and their contained proofs and commitments,
//! which are crucial for L2 block finality.
//!
//! ## L2 Block Processing Flow
//!
//! ### 1. Block Synchronization
//! The system fetches L2 blocks from the sequencer in batches, implementing adaptive batch sizing
//! based on response size. Blocks are sorted to ensure correct processing order.
//!
//! ### 2. Block Processing
//! Each L2 block goes through several processing steps:
//!
//! 1. **Initial Validation**
//!    - Verifies the block's previous hash matches the current chain state
//!    - Creates storage for the next L2 height
//!    - Registers the block with the fork manager
//!
//! 2. **Transaction Processing**
//!    - Decodes and processes system transactions
//!    - Updates short header proofs for L1 blocks referenced in system transactions
//!    - Handles EVM transactions and system calls
//!
//! 3. **State Transition Function (STF)**
//!    The STF is a critical component that handles state transitions for L2 blocks. It implements
//!    the core logic for processing transactions and maintaining the rollup's state. The STF is
//!    implemented using the `StfBlueprint` which provides a framework for state transitions:
//!
//!    a. **Pre-Transition Setup**
//!       - Creates a new storage instance for the block using `ProverStorageManager`
//!       - Verifies the current block's `prev_hash` matches the previous block's hash.
//!       - Prepares the execution context with the current fork specification
//!       - Initializes the runtime environment with necessary parameters:
//!         * Current fork specification
//!         * Sequencer public key for signature verification
//!         * Current state root for validation
//!         * Storage instance for state changes
//!
//!    b. **Transaction Execution**
//!       - Processes transactions in the block's order using the `CitreaRuntime`
//!       - For each transaction:
//!         * Validates transaction format and signature
//!         * Decodes transaction data into appropriate message types
//!         * Applies state changes atomically within a transaction context
//!         * Handles system calls and EVM transactions through the runtime
//!         * Maintains gas accounting and execution limits
//!         * Records state changes in a change set for atomic commits
//!       - Special handling for system transactions:
//!         * Bitcoin Light Client contract initialization
//!         * Bridge contract initialization
//!         * L1 Block info updates
//!         * Bridge deposits
//!
//!    c. **Post-Transition Validation**
//!       - Verifies the new state root matches the block's state root
//!       - Validates all state transitions are consistent
//!       - Ensures proper handling of fork-specific logic
//!
//!    d. **State Finalization**
//!       - Commits state changes to storage using the change set
//!       - Updates state root and block hash
//!       - Finalizes the storage instance for the block
//!       - Updates metrics and monitoring data
//!
//!    e. **Error Handling and Recovery**
//!       - Implements atomic transaction processing
//!       - Handles transaction failures gracefully
//!       - Maintains state consistency during errors
//!
//!    f. **Fork Management**
//!       - Handles fork transitions based on block height
//!       - Applies fork-specific validation rules using the spec's image ID.
//!       - Manages code commitments for different forks
//!       - Ensures proper state transitions across forks
//!
//! 4. **Block Commitment**
//!    - Computes transaction hashes
//!    - Commits the block to the ledger database
//!    - Updates metrics and state tracking
//!
//! ## Integration with L1
//!
//! The L2 block processing is tightly integrated with L1 through:
//! - Sequencer commitments posted to L1
//! - ZK proofs for state transitions
//! - Short header proofs for L1 block references
//! - Finality tracking through L1 block processing
//!
//! This comprehensive system ensures that L2 blocks are processed correctly, maintaining
//! the security and consistency of the rollup chain while providing efficient
//! synchronization and state management.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::{InitParams, RollupPublicKeys, RunnerConfig};
use citrea_stf::runtime::CitreaRuntime;
use citrea_storage_ops::pruning::{Pruner, PrunerService};
use da_block_handler::L1BlockHandler;
use jsonrpsee::RpcModule;
pub use l2_syncer::L2Syncer;
use sov_db::ledger_db::NodeLedgerOps;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::fork::ForkManager;
use sov_modules_api::{SpecId, Zkvm};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::{broadcast, Mutex};

/// Module for handling L1 data availability blocks
pub mod da_block_handler;
/// Module containing database migration definitions
pub mod db_migrations;
/// Module containing error definitions
mod error;
/// Module for L2 block synchronization
mod l2_syncer;
/// Module for metrics collection
mod metrics;
/// Module providing RPC functionality
pub mod rpc;

/// Builds and initializes all fullnode services
///
/// # Arguments
/// * `runner_config` - Configuration for the fullnode
/// * `init_params` - Initial parameters for node setup
/// * `native_stf` - State transition function blueprint
/// * `public_keys` - Rollup public keys containing the sequencer's and batch prover's keys for cryptographic operations
/// * `da_service` - Data availability service implementation
/// * `ledger_db` - Database for ledger operations
/// * `storage_manager` - Manager for prover storage
/// * `l2_block_tx` - Channel for L2 block notifications
/// * `fork_manager` - Manager for handling chain forks
/// * `code_commitments` - Map of ZKVM code commitments by spec ID
/// * `rpc_module` - RPC module for external communication
/// * `backup_manager` - Manager for backup operations
///
/// # Type Parameters
/// * `DA` - Data availability service type
/// * `DB` - Database type implementing NodeLedgerOps
/// * `Vm` - ZKVM implementation type
///
/// # Returns
/// A tuple containing:
/// - L2Syncer for block synchronization
/// - L1BlockHandler for DA block processing
/// - Optional PrunerService for historical data pruning
/// - Configured RPC module
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<DA, DB, Vm>(
    runner_config: RunnerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<
        DefaultContext,
        <DA as DaService>::Spec,
        CitreaRuntime<DefaultContext, <DA as DaService>::Spec>,
    >,
    public_keys: RollupPublicKeys,
    da_service: Arc<DA>,
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    l2_block_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    code_commitments: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
    rpc_module: RpcModule<()>,
    backup_manager: Arc<BackupManager>,
) -> Result<(
    L2Syncer<DA, DB>,
    L1BlockHandler<Vm, DA, DB>,
    Option<PrunerService>,
    RpcModule<()>,
)>
where
    DA: DaService<Error = anyhow::Error>,
    DB: NodeLedgerOps + Send + Sync + Clone + 'static,
    Vm: ZkvmHost + Zkvm,
{
    let rpc_context = rpc::create_rpc_context(ledger_db.clone());
    let rpc_module = rpc::register_rpc_methods(rpc_module, rpc_context)?;

    let last_pruned_block = ledger_db.get_last_pruned_l2_height()?.unwrap_or(0);
    let pruner = runner_config.pruning_config.as_ref().map(|pruning_config| {
        let pruner = Pruner::new(
            pruning_config.clone(),
            ledger_db.inner(),
            storage_manager.get_state_db_handle(),
            storage_manager.get_native_db_handle(),
        );

        PrunerService::new(pruner, last_pruned_block, l2_block_tx.subscribe())
    });

    let include_tx_bodies = runner_config.include_tx_body;
    let l2_syncer = L2Syncer::new(
        runner_config,
        init_params,
        native_stf,
        public_keys.clone(),
        da_service.clone(),
        ledger_db.clone(),
        storage_manager,
        fork_manager,
        l2_block_tx,
        backup_manager.clone(),
        include_tx_bodies,
    )?;

    let l1_block_handler = L1BlockHandler::new(
        ledger_db,
        da_service,
        public_keys.sequencer_da_pub_key,
        public_keys.prover_da_pub_key,
        code_commitments,
        Arc::new(Mutex::new(L1BlockCache::new())),
        backup_manager,
    );

    Ok((l2_syncer, l1_block_handler, pruner, rpc_module))
}
