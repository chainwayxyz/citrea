use std::sync::Arc;

use anyhow::Context as _;
use ethereum_rpc::{EthRpcConfig, FeeHistoryCacheConfig, GasPriceOracleConfig};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_prover_storage_manager::SnapshotManager;
use sov_rollup_interface::services::da::DaService;
use sov_state::ProverStorage;
use tokio::sync::broadcast;

// register ethereum methods.
pub(crate) fn register_ethereum<Da: DaService>(
    da_service: Arc<Da>,
    storage: ProverStorage<SnapshotManager>,
    ledger_db: LedgerDB,
    methods: &mut jsonrpsee::RpcModule<()>,
    sequencer_client_url: Option<String>,
    soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
) -> Result<(), anyhow::Error> {
    let eth_rpc_config = {
        EthRpcConfig {
            gas_price_oracle_config: GasPriceOracleConfig::default(),
            fee_history_cache_config: FeeHistoryCacheConfig::default(),
        }
    };

    let ethereum_rpc = ethereum_rpc::create_rpc_module::<DefaultContext, Da>(
        da_service,
        eth_rpc_config,
        storage,
        ledger_db,
        sequencer_client_url,
        soft_confirmation_rx,
    );
    methods
        .merge(ethereum_rpc)
        .context("Failed to merge Ethereum RPC modules")
}
