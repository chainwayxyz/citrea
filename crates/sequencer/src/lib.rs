use std::sync::Arc;

use anyhow::Result;
pub use citrea_common::SequencerConfig;
use citrea_common::{InitParams, RollupPublicKeys};
use db_provider::DbProvider;
use deposit_data_mempool::DepositDataMempool;
use jsonrpsee::RpcModule;
use mempool::CitreaMempool;
use parking_lot::Mutex;
pub use rpc::SequencerRpcClient;
pub use runner::CitreaSequencer;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_api::{Context, Spec};
use sov_modules_stf_blueprint::{Runtime, StfBlueprint};
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_state::ProverStorage;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;

mod commitment;
pub mod db_migrations;
mod db_provider;
mod deposit_data_mempool;
mod mempool;
mod metrics;
pub mod rpc;
mod runner;
mod utils;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<C, Da, DB, RT>(
    sequencer_config: SequencerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<C, <Da as DaService>::Spec, RT>,
    public_keys: RollupPublicKeys,
    da_service: Arc<Da>,
    ledger_db: DB,
    storage_manager: ProverStorageManager<Da::Spec>,
    prover_storage: ProverStorage<SnapshotManager>,
    soft_confirmation_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    rpc_module: RpcModule<()>,
) -> Result<(CitreaSequencer<C, Da, DB, RT>, RpcModule<()>)>
where
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>>,
    Da: DaService,
    DB: SequencerLedgerOps + Send + Sync + Clone + 'static,
    RT: Runtime<C, Da::Spec>,
{
    let (l2_force_block_tx, l2_force_block_rx) = unbounded_channel();
    // used as client of reth's mempool
    let db_provider = DbProvider::new(prover_storage.clone());
    let mempool = Arc::new(CitreaMempool::new(
        db_provider.clone(),
        sequencer_config.mempool_conf.clone(),
    )?);
    let deposit_mempool = Arc::new(Mutex::new(DepositDataMempool::new()));

    let rpc_context = rpc::create_rpc_context(
        mempool.clone(),
        deposit_mempool.clone(),
        l2_force_block_tx,
        prover_storage.clone(),
        ledger_db.clone(),
        sequencer_config.test_mode,
    );
    let rpc_module = rpc::register_rpc_methods::<C, DB>(rpc_context, rpc_module)?;

    let seq = CitreaSequencer::new(
        da_service,
        sequencer_config,
        init_params,
        native_stf,
        storage_manager,
        public_keys,
        ledger_db,
        db_provider,
        mempool,
        deposit_mempool,
        fork_manager,
        soft_confirmation_tx,
        l2_force_block_rx,
    )
    .unwrap();

    Ok((seq, rpc_module))
}
