use std::sync::Mutex;

#[cfg(feature = "local")]
use citrea_evm::DevSigner;
use citrea_evm::Evm;
use reth_primitives::U256;
use reth_rpc_types::trace::geth::GethTrace;
use rustc_version_runtime::version;
use schnellru::{ByLength, LruMap};
use sequencer_client::SequencerClient;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::CITREA_VERSION;
use tokio::sync::broadcast;
use tracing::instrument;

use crate::gas_price::fee_history::FeeHistoryCacheConfig;
use crate::gas_price::gas_oracle::{GasPriceOracle, GasPriceOracleConfig};

const MAX_TRACE_BLOCK: u32 = 1000;

#[derive(Clone)]
pub struct EthRpcConfig {
    pub gas_price_oracle_config: GasPriceOracleConfig,
    pub fee_history_cache_config: FeeHistoryCacheConfig,
    #[cfg(feature = "local")]
    pub eth_signer: DevSigner,
}

pub struct Ethereum<C: sov_modules_api::Context, Da: DaService> {
    #[allow(dead_code)]
    pub(crate) da_service: Da,
    pub(crate) gas_price_oracle: GasPriceOracle<C>,
    #[cfg(feature = "local")]
    pub(crate) eth_signer: DevSigner,
    pub(crate) storage: C::Storage,
    pub(crate) sequencer_client: Option<SequencerClient>,
    pub(crate) web3_client_version: String,
    pub(crate) trace_cache: Mutex<LruMap<u64, Vec<GethTrace>, ByLength>>,
    pub(crate) soft_commitment_tx: broadcast::Sender<u64>,
}

impl<C: sov_modules_api::Context, Da: DaService> Ethereum<C, Da> {
    pub(crate) fn new(
        da_service: Da,
        gas_price_oracle_config: GasPriceOracleConfig,
        fee_history_cache_config: FeeHistoryCacheConfig,
        #[cfg(feature = "local")] eth_signer: DevSigner,
        storage: C::Storage,
        sequencer_client: Option<SequencerClient>,
        soft_commitment_tx: broadcast::Sender<u64>,
    ) -> Self {
        let evm = Evm::<C>::default();
        let gas_price_oracle =
            GasPriceOracle::new(evm, gas_price_oracle_config, fee_history_cache_config);

        let rollup = "citrea";
        let arch = std::env::consts::ARCH;
        let rustc_v = version();

        let current_version = format!("{}/{}/{}/rust-{}", rollup, CITREA_VERSION, arch, rustc_v);

        let trace_cache = Mutex::new(LruMap::new(ByLength::new(MAX_TRACE_BLOCK)));

        Self {
            da_service,
            gas_price_oracle,
            #[cfg(feature = "local")]
            eth_signer,
            storage,
            sequencer_client,
            web3_client_version: current_version,
            trace_cache,
            soft_commitment_tx,
        }
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) async fn max_fee_per_gas(&self, working_set: &mut WorkingSet<C>) -> (U256, U256) {
        let suggested_tip = self
            .gas_price_oracle
            .suggest_tip_cap(working_set)
            .await
            .unwrap();

        let evm = Evm::<C>::default();
        let base_fee = evm
            .get_block_by_number(None, None, working_set)
            .unwrap()
            .unwrap()
            .header
            .base_fee_per_gas
            .unwrap_or_default();

        (U256::from(base_fee), U256::from(suggested_tip))
    }

    //     fn make_raw_tx(
    //         &self,
    //         raw_tx: RlpEvmTransaction,
    //     ) -> Result<(B256, Vec<u8>), jsonrpsee::core::RegisterMethodError> {
    //         let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

    //         let tx_hash = signed_transaction.hash();

    //         let tx = CallMessage { txs: vec![raw_tx] };
    //         let message = <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(tx);

    //         Ok((B256::from(tx_hash), message))
    //     }
}
