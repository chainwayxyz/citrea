use std::str::FromStr;
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
    storage: ProverStorage<sov_state::DefaultStorageSpec, SnapshotManager>,
    ledger_db: LedgerDB,
    methods: &mut jsonrpsee::RpcModule<()>,
    sequencer_client_url: Option<String>,
    soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
) -> Result<(), anyhow::Error> {
    let eth_rpc_config = {
        let eth_signer = eth_dev_signer();
        EthRpcConfig {
            eth_signer,
            gas_price_oracle_config: GasPriceOracleConfig::default(),
            fee_history_cache_config: FeeHistoryCacheConfig::default(),
        }
    };

    let ethereum_rpc = ethereum_rpc::get_ethereum_rpc::<DefaultContext, Da>(
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

// TODO: #840
fn eth_dev_signer() -> ethereum_rpc::DevSigner {
    ethereum_rpc::DevSigner::new(vec![secp256k1::SecretKey::from_str(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .unwrap()])
}
