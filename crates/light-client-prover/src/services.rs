//! This module provides functionality for building the services required for running the Citrea Light Client Prover.
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use citrea_common::backup::BackupManager;
use citrea_common::LightClientProverConfig;
use jsonrpsee::RpcModule;
use prover_services::ParallelProverService;
use sov_db::ledger_db::{LightClientProverLedgerOps, SharedLedgerOps};
use sov_modules_api::{SpecId, Zkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_rollup_interface::Network;

use crate::circuit::initial_values::InitialValueProvider;
use crate::da_block_handler::L1BlockHandler;
use crate::rpc;

/// Builds and initializes all light client prover services
///
/// # Arguments
/// * `network` - The Citrea network for the L1 block handler
/// * `prover_config` - Proving configuration for the light client prover
/// * `runner_config` - Runner configuration for the light client prover
/// * `storage_manager` - Manager for prover storage
/// * `ledger_db` - Database for ledger operations
/// * `da_service` - Data availability service implementation
/// * `prover_service` - Parallel prover service for handling ZKVM operations
/// * `light_client_prover_code_commitments` - Map of ZKVM code commitments by spec ID for the light client proof circuit
/// * `light_client_prover_elfs` - Map of ZKVM ELF binaries by spec ID for the light client proof circuit
/// * `rpc_module` - RPC module for external communication
/// * `backup_manager` - Manager for backup operations
///
/// # Type Parameters
/// * `Da` - Data availability service type
/// * `DB` - Database type implementing LightClientProverLedgerOps and SharedLedgerOps
/// * `Vm` - ZKVM implementation type
///
/// # Returns
/// A tuple containing:
/// - Light client prover runner
/// - L1BlockHandler for DA block processing
/// - Configured RPC module
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<Vm, Da, DB>(
    network: Network,
    prover_config: LightClientProverConfig,
    storage_manager: ProverStorageManager,
    ledger_db: DB,
    da_service: Arc<Da>,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    light_client_prover_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_prover_elfs: HashMap<SpecId, Vec<u8>>,
    rpc_module: RpcModule<()>,
    backup_manager: Arc<BackupManager>,
) -> Result<(L1BlockHandler<Vm, Da, DB>, RpcModule<()>)>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone + 'static,
    Network: InitialValueProvider<Da::Spec>,
{
    let rpc_storage = storage_manager.create_final_view_storage();
    let rpc_context = rpc::create_rpc_context(ledger_db.clone(), rpc_storage);
    let rpc_module = rpc::register_rpc_methods(rpc_module, rpc_context)?;

    let l1_block_handler = L1BlockHandler::new(
        network,
        prover_config,
        prover_service,
        storage_manager,
        ledger_db,
        da_service,
        light_client_prover_code_commitments,
        light_client_prover_elfs,
        backup_manager,
    );

    Ok((l1_block_handler, rpc_module))
}
