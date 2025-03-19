use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use citrea_common::backup::BackupManager;
use citrea_common::{LightClientProverConfig, RunnerConfig};
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
use crate::runner::CitreaLightClientProver;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<Vm, Da, DB>(
    network: Network,
    prover_config: LightClientProverConfig,
    runner_config: RunnerConfig,
    storage_manager: ProverStorageManager,
    ledger_db: DB,
    da_service: Arc<Da>,
    prover_service: Arc<ParallelProverService<Da, Vm>>,
    light_client_prover_code_commitments: HashMap<SpecId, Vm::CodeCommitment>,
    light_client_prover_elfs: HashMap<SpecId, Vec<u8>>,
    rpc_module: RpcModule<()>,
    backup_manager: Arc<BackupManager>,
) -> Result<(
    CitreaLightClientProver,
    L1BlockHandler<Vm, Da, DB>,
    RpcModule<()>,
)>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    DB: LightClientProverLedgerOps + SharedLedgerOps + Clone + 'static,
    Network: InitialValueProvider<Da::Spec>,
{
    let rpc_context = rpc::create_rpc_context(ledger_db.clone());
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

    let prover = CitreaLightClientProver::new(runner_config)?;

    Ok((prover, l1_block_handler, rpc_module))
}
