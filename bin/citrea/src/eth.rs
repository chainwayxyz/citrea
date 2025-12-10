use std::sync::Arc;

use anyhow::Context as _;
use citrea_common::RpcConfig;
use ethereum_rpc::{EthRpcConfig, FeeHistoryCacheConfig, GasPriceOracleConfig};
use reth_tasks::TaskExecutor;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_rollup_interface::services::da::DaService;
use sov_state::ProverStorage;
use tokio::sync::broadcast;

/// Register ethereum methods.
#[allow(clippy::too_many_arguments)]
pub fn register_ethereum<Da: DaService>(
    da_service: Arc<Da>,
    storage: ProverStorage,
    rpc_config: RpcConfig,
    ledger_db: LedgerDB,
    methods: &mut jsonrpsee::RpcModule<()>,
    sequencer_client_url: Option<String>,
    l2_block_rx: Option<broadcast::Receiver<u64>>,
    task_executor: TaskExecutor,
) -> Result<(), anyhow::Error> {
    let eth_rpc_config = {
        EthRpcConfig {
            gas_price_oracle_config: GasPriceOracleConfig::default(),
            fee_history_cache_config: FeeHistoryCacheConfig::default(),
            stale_filter_ttl: rpc_config.stale_filter_ttl,
            enable_filters: rpc_config.enable_filters,
        }
    };

    let ethereum_rpc = ethereum_rpc::create_rpc_module::<DefaultContext, Da>(
        da_service,
        eth_rpc_config,
        rpc_config,
        storage,
        ledger_db,
        sequencer_client_url,
        l2_block_rx,
        task_executor,
    );
    methods
        .merge(ethereum_rpc)
        .context("Failed to merge Ethereum RPC modules")
}
