//! This module is a mix of full node and sequencer. It is a special node type with the purpose of fetching pre tangerine blocks from the current sequencer and converting them to tangerine blocks.
//! After this is synced at some point we will shut down the current pre Tangerine sequencer and start a new Tangerine sequencer with the state of this node, the new sequencer will be publishing Tangerine blocks after that
//! Thanks to this we were able to remove all backwards compat
//! This module will be removed after the testnet deployment

use std::sync::Arc;

use anyhow::Result;
use citrea_common::InitParams;
pub use citrea_common::SequencerConfig;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use jsonrpsee::RpcModule;
use parking_lot::Mutex;
use reth_tasks::TaskExecutor;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::services::da::DaService;
use syncing::CitreaReorgSequencer;
use tokio::sync::broadcast;
use tokio::sync::mpsc::unbounded_channel;

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::{CitreaMempool, DbProvider};
use crate::rpc;

pub mod syncing;
mod types;
mod utils;

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_reorg_services<Da, DB>(
    sequencer_config: SequencerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<
        DefaultContext,
        <Da as DaService>::Spec,
        CitreaRuntime<DefaultContext, <Da as DaService>::Spec>,
    >,
    da_service: Arc<Da>,
    ledger_db: DB,
    storage_manager: ProverStorageManager,
    rpc_module: RpcModule<()>,
    _l2_block_tx: broadcast::Sender<u64>,
    task_executor: TaskExecutor,
) -> Result<(CitreaReorgSequencer<Da, DB>, RpcModule<()>)>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Sync + Clone + 'static,
{
    let (l2_force_block_tx, _) = unbounded_channel();
    // used as client of reth's mempool
    let db_provider_storage = storage_manager.create_final_view_storage();
    let db_provider = DbProvider::new(db_provider_storage);
    let mempool = Arc::new(CitreaMempool::new(
        db_provider.clone(),
        sequencer_config.mempool_conf.clone(),
        task_executor,
    )?);
    let deposit_mempool = Arc::new(Mutex::new(DepositDataMempool::new()));
    let rpc_storage = storage_manager.create_final_view_storage();
    let rpc_context = rpc::create_rpc_context(
        mempool.clone(),
        deposit_mempool.clone(),
        l2_force_block_tx,
        rpc_storage,
        ledger_db.clone(),
        sequencer_config.test_mode,
    );
    let rpc_module = rpc::register_rpc_methods::<DB>(rpc_context, rpc_module)?;

    let seq = CitreaReorgSequencer::new(
        init_params,
        da_service,
        ledger_db,
        sequencer_config,
        native_stf,
        storage_manager,
    );

    Ok((seq, rpc_module))
}
