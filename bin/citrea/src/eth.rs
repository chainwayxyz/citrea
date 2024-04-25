use std::str::FromStr;

use anyhow::Context as _;
use ethereum_rpc::{EthRpcConfig, FeeHistoryCacheConfig, GasPriceOracleConfig};
use sequencer_client::SequencerClient;
use sov_modules_api::{Context, Spec};
use sov_rollup_interface::services::da::DaService;
use tokio::sync::watch;

// register ethereum methods.
pub(crate) fn register_ethereum<C: Context, Da: DaService>(
    da_service: Da,
    storage: watch::Receiver<<C as Spec>::Storage>,
    methods: &mut jsonrpsee::RpcModule<()>,
    sequencer_client: Option<SequencerClient>,
) -> Result<(), anyhow::Error> {
    let eth_rpc_config = {
        let eth_signer = eth_dev_signer();
        EthRpcConfig {
            eth_signer,
            gas_price_oracle_config: GasPriceOracleConfig::default(),
            fee_history_cache_config: FeeHistoryCacheConfig::default(),
        }
    };

    let ethereum_rpc = ethereum_rpc::get_ethereum_rpc::<C, Da>(
        da_service,
        eth_rpc_config,
        storage,
        sequencer_client,
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
