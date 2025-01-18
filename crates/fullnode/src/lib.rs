use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use citrea_common::cache::L1BlockCache;
use citrea_common::{RollupPublicKeys, RunnerConfig};
use da_block_handler::L1BlockHandler;
use jsonrpsee::RpcModule;
pub use runner::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sov_db::ledger_db::NodeLedgerOps;
use sov_modules_api::fork::ForkManager;
use sov_modules_api::{Context, Spec, SpecId, Zkvm};
use sov_modules_stf_blueprint::{Runtime, StfBlueprint};
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::ZkvmHost;
use sov_state::ProverStorage;
use sov_stf_runner::InitVariant;
use tokio::sync::{broadcast, Mutex};

pub mod da_block_handler;
pub mod db_migrations;
mod metrics;
mod runner;

pub fn build_services<Da, C, DB, RT, Vm, StateRoot>(
    runner_config: RunnerConfig,
    init_variant: InitVariant<StfBlueprint<C, Da::Spec, RT>, Da::Spec>,
    public_keys: RollupPublicKeys,
    da_service: Arc<Da>,
    ledger_db: DB,
    storage_manager: ProverStorageManager<Da::Spec>,
    soft_confirmation_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    code_commitments: HashMap<SpecId, <Vm as Zkvm>::CodeCommitment>,
    rpc_module: RpcModule<()>,
) -> Result<(
    CitreaFullnode<Da, C, DB, RT>,
    L1BlockHandler<C, Vm, Da, StateRoot, DB>,
    RpcModule<()>,
)>
where
    Da: DaService<Error = anyhow::Error>,
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>> + Send + Sync,
    DB: NodeLedgerOps + Send + Sync + Clone + 'static,
    RT: Runtime<C, Da::Spec>,
    Vm: ZkvmHost + Zkvm,
    StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug,
{
    let native_stf = StfBlueprint::new();
    let runner = CitreaFullnode::new(
        runner_config,
        public_keys.clone(),
        da_service.clone(),
        ledger_db.clone(),
        native_stf,
        storage_manager,
        init_variant,
        fork_manager,
        soft_confirmation_tx,
    )?;

    let l1_block_handler = L1BlockHandler::new(
        ledger_db,
        da_service,
        public_keys.sequencer_public_key,
        public_keys.sequencer_da_pub_key,
        public_keys.prover_da_pub_key,
        code_commitments,
        Arc::new(Mutex::new(L1BlockCache::new())),
    );

    Ok((runner, l1_block_handler, rpc_module))
}
