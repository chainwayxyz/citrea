use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use borsh::BorshDeserialize;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::{BatchProverConfig, InitParams, RollupPublicKeys, RunnerConfig};
use citrea_stf::runtime::CitreaRuntime;
use da_block_handler::L1BlockHandler;
use jsonrpsee::RpcModule;
use l2_syncer::L2Syncer;
use prover_services::ParallelProverService;
pub use proving::GroupCommitments;
pub use runner::*;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_keys::default_signature::K256PublicKey;
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
mod errors;
mod l2_syncer;
mod metrics;
mod proving;
pub mod rpc;
mod runner;

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
    CitreaBatchProver<DA, DB>,
    L1BlockHandler<Vm, DA, DB>,
    RpcModule<()>,
)>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + 'static,
    Vm: ZkvmHost + Zkvm + 'static,
{
    let l1_block_cache = Arc::new(Mutex::new(L1BlockCache::new()));

    let rpc_context = rpc::create_rpc_context::<DA, Vm, DB>(
        da_service.clone(),
        prover_service.clone(),
        ledger_db.clone(),
        storage_manager.clone(),
        public_keys.sequencer_da_pub_key.clone(),
        K256PublicKey::try_from_slice(&public_keys.sequencer_public_key.clone())?,
        l1_block_cache,
        code_commitments.clone(),
        elfs.clone(),
    );
    let rpc_module = rpc::register_rpc_methods::<DA, Vm, DB>(rpc_context, rpc_module)?;

    let l2_syncer = L2Syncer::new(
        runner_config,
        init_params,
        native_stf,
        public_keys.clone(),
        da_service.clone(),
        ledger_db.clone(),
        storage_manager.clone(),
        fork_manager,
        l2_block_tx,
        backup_manager.clone(),
        true,
    )?;

    let batch_prover = CitreaBatchProver::new(l2_syncer)?;

    let skip_submission_until_l1 =
        std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1").map_or(0u64, |v| v.parse().unwrap_or(0));

    let l1_block_handler = L1BlockHandler::new(
        prover_config,
        prover_service,
        ledger_db,
        storage_manager,
        da_service,
        public_keys,
        code_commitments,
        elfs,
        skip_submission_until_l1,
        Arc::new(Mutex::new(L1BlockCache::new())),
        backup_manager,
    );
    Ok((batch_prover, l1_block_handler, rpc_module))
}
