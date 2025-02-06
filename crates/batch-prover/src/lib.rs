use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::{BatchProverConfig, RollupPublicKeys, RunnerConfig};
use da_block_handler::L1BlockHandler;
use jsonrpsee::RpcModule;
pub use proving::GroupCommitments;
pub use runner::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_modules_api::fork::ForkManager;
use sov_modules_api::{Context, Spec, SpecId, Zkvm};
use sov_modules_stf_blueprint::{Runtime, StfBlueprint};
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager, SnapshotManager};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitParams, ProverService};
use tokio::sync::{broadcast, Mutex};

pub mod da_block_handler;
pub mod db_migrations;
mod errors;
mod metrics;
mod proving;
pub mod rpc;
mod runner;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub async fn build_services<C, Da, DB, RT, Vm, Ps, Witness, Tx>(
    prover_config: BatchProverConfig,
    runner_config: RunnerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<C, <Da as DaService>::Spec, RT>,
    public_keys: RollupPublicKeys,
    da_service: Arc<Da>,
    prover_service: Arc<Ps>,
    ledger_db: DB,
    storage_manager: ProverStorageManager<Da::Spec>,
    soft_confirmation_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    code_commitments: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
    elfs: HashMap<SpecId, Vec<u8>>,
    rpc_module: RpcModule<()>,
) -> Result<(
    CitreaBatchProver<C, Da, DB, RT>,
    L1BlockHandler<Vm, Da, Ps, DB, Witness, Tx>,
    RpcModule<()>,
)>
where
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>>,
    Da: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + 'static,
    RT: Runtime<C, Da::Spec>,
    Vm: ZkvmHost + Zkvm + 'static,
    Ps: ProverService<DaService = Da> + Send + Sync + 'static,
    Witness: Default + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned,
    Tx: Clone + BorshSerialize + BorshDeserialize,
{
    let l1_block_cache = Arc::new(Mutex::new(L1BlockCache::new()));

    let rpc_context = rpc::create_rpc_context::<C, Da, Ps, Vm, DB, RT>(
        da_service.clone(),
        prover_service.clone(),
        ledger_db.clone(),
        public_keys.sequencer_da_pub_key.clone(),
        public_keys.sequencer_public_key.clone(),
        l1_block_cache,
        code_commitments.clone(),
        elfs.clone(),
    );
    let rpc_module = rpc::register_rpc_methods::<C, Da, Ps, Vm, DB, RT>(rpc_context, rpc_module)?;

    let batch_prover = CitreaBatchProver::new(
        runner_config,
        init_params,
        native_stf,
        public_keys.clone(),
        da_service.clone(),
        ledger_db.clone(),
        storage_manager,
        fork_manager,
        soft_confirmation_tx,
    )?;
    let skip_submission_until_l1 =
        std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1").map_or(0u64, |v| v.parse().unwrap_or(0));

    let l1_block_handler = L1BlockHandler::new(
        prover_config,
        prover_service,
        ledger_db,
        da_service,
        public_keys.sequencer_public_key,
        public_keys.sequencer_da_pub_key,
        code_commitments,
        elfs,
        skip_submission_until_l1,
        Arc::new(Mutex::new(L1BlockCache::new())),
    );
    Ok((batch_prover, l1_block_handler, rpc_module))
}
