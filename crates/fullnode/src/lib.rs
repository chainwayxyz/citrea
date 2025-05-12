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

pub mod da_block_handler;
pub mod db_migrations;
mod error;
mod l2_syncer;
mod metrics;
pub mod rpc;

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
