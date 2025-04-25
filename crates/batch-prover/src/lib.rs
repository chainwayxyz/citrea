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

pub mod db_migrations;
pub mod l1_syncer;
mod l2_syncer;
mod metrics;
mod partition;
pub mod prover;
pub mod rpc;

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
