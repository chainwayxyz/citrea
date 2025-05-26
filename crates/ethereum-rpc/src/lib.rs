mod ethereum;
mod gas_price;
mod subscription;
mod trace;

use std::sync::Arc;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256, U64};
use alloy_rpc_types::serde_helpers::JsonStorageKey;
use alloy_rpc_types::{
    BlockId, BlockNumberOrTag, EIP1186AccountProofResponse, FeeHistory, Filter, Index, Transaction,
};
use alloy_rpc_types_trace::geth::{GethDebugTracingOptions, GethTrace, TraceResult};
use citrea_evm::{generate_eth_proof, Evm};
use citrea_sequencer::SequencerRpcClient;
pub use ethereum::{EthRpcConfig, Ethereum};
pub use gas_price::fee_history::FeeHistoryCacheConfig;
pub use gas_price::gas_oracle::GasPriceOracleConfig;
use jsonrpsee::core::{RpcResult, SubscriptionResult};
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{PendingSubscriptionSink, RpcModule};
use reth_rpc_eth_types::EthApiError;
use serde_json::{json, Value};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use sov_state::storage::NativeStorage;
use tokio::join;
use tokio::sync::broadcast;
use trace::{debug_trace_by_block_number, handle_debug_trace_chain};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncValues {
    pub head_block_number: U64,
    pub synced_block_number: U64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum LayerStatus {
    Synced(U64),
    Syncing(SyncValues),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub l1_status: LayerStatus,
    pub l2_status: LayerStatus,
}

#[rpc(server)]
pub trait EthereumRpc {
    /// Returns the client version.
    #[method(name = "web3_clientVersion")]
    fn web3_client_version(&self) -> RpcResult<String>;

    /// Returns Keccak-256 hash of the given data.
    #[method(name = "web3_sha3")]
    #[blocking]
    fn web3_sha3(&self, data: Bytes) -> RpcResult<B256>;

    /// Returns the current gas price.
    #[method(name = "eth_gasPrice")]
    #[blocking]
    fn eth_gas_price(&self) -> RpcResult<U256>;

    /// Returns the maximum fee per gas.
    #[method(name = "eth_maxFeePerGas")]
    #[blocking]
    fn eth_max_fee_per_gas(&self) -> RpcResult<U256>;

    /// Returns the maximum priority fee per gas.
    #[method(name = "eth_maxPriorityFeePerGas")]
    #[blocking]
    fn eth_max_priority_fee_per_gas(&self) -> RpcResult<U256>;

    /// Returns fee history.
    #[method(name = "eth_feeHistory")]
    #[blocking]
    fn eth_fee_history(
        &self,
        block_count: Index,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory>;

    /// Returns zkproof by EIP-1186.
    #[method(name = "eth_getProof")]
    #[blocking]
    fn eth_get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_id: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse>;

    /// Returns traces for a block by hash.
    #[method(name = "debug_traceBlockByHash")]
    #[blocking]
    fn debug_trace_block_by_hash(
        &self,
        block_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>>;

    /// Returns traces for a block by number.
    #[method(name = "debug_traceBlockByNumber")]
    #[blocking]
    fn debug_trace_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>>;

    /// Returns trace for a transaction.
    #[method(name = "debug_traceTransaction")]
    #[blocking]
    fn debug_trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<GethTrace>;

    /// Returns the transaction pool content.
    #[method(name = "txpool_content")]
    fn txpool_content(&self) -> RpcResult<Value>;

    /// Gets uncle by block hash and index.
    #[method(name = "eth_getUncleByBlockHashAndIndex")]
    fn get_uncle_by_block_hash_and_index(
        &self,
        block_hash: String,
        uncle_index: String,
    ) -> RpcResult<Value>;

    /// Sends raw transaction (full node only).
    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256>;

    /// Gets transaction by hash (full node only).
    #[method(name = "eth_getTransactionByHash")]
    async fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>>;

    /// Gets sync status (full node only).
    #[method(name = "citrea_syncStatus")]
    async fn citrea_sync_status(&self) -> RpcResult<SyncStatus>;

    /// Subscribe to debug events.
    #[subscription(name = "debug_subscribe" => "debug_subscription", unsubscribe = "debug_unsubscribe", item = GethTrace)]
    async fn subscribe_debug(
        &self,
        topic: String,
        start_block: BlockNumberOrTag,
        end_block: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> SubscriptionResult;

    /// Subscribe to Ethereum events.
    #[subscription(name = "eth_subscribe" => "eth_subscription", unsubscribe = "eth_unsubscribe", item = Value)]
    async fn subscribe_eth(&self, topic: String, filter: Option<Filter>) -> SubscriptionResult;
}

const ETH_RPC_ERROR: &str = "ETH_RPC_ERROR";

fn to_eth_rpc_error(err: impl ToString) -> ErrorObjectOwned {
    to_jsonrpsee_error_object(ETH_RPC_ERROR, err)
}

pub struct EthereumRpcServerImpl<C, Da>
where
    C: sov_modules_api::Context,
    Da: DaService,
{
    ethereum: Arc<Ethereum<C, Da>>,
}

impl<C, Da> EthereumRpcServerImpl<C, Da>
where
    C: sov_modules_api::Context,
    Da: DaService,
{
    pub fn new(ethereum: Arc<Ethereum<C, Da>>) -> Self {
        Self { ethereum }
    }
}

#[async_trait::async_trait]
impl<C, Da> EthereumRpcServer for EthereumRpcServerImpl<C, Da>
where
    C: sov_modules_api::Context,
    C::Storage: NativeStorage,
    Da: DaService,
{
    fn web3_client_version(&self) -> RpcResult<String> {
        Ok(self.ethereum.web3_client_version.clone())
    }

    fn web3_sha3(&self, data: Bytes) -> RpcResult<B256> {
        Ok(B256::from_slice(keccak256(&data).as_slice()))
    }

    fn eth_gas_price(&self) -> RpcResult<U256> {
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());
        let (base_fee, suggested_tip) = self.ethereum.max_fee_per_gas(&mut working_set);
        Ok(suggested_tip + base_fee)
    }

    fn eth_max_fee_per_gas(&self) -> RpcResult<U256> {
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());
        let (base_fee, suggested_tip) = self.ethereum.max_fee_per_gas(&mut working_set);
        Ok(suggested_tip + base_fee)
    }

    fn eth_max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());
        let (_base_fee, suggested_tip) = self.ethereum.max_fee_per_gas(&mut working_set);
        Ok(suggested_tip)
    }

    fn eth_fee_history(
        &self,
        block_count: Index,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        let block_count = block_count.0 as u64;
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());

        self.ethereum
            .gas_price_oracle
            .fee_history(
                block_count,
                newest_block,
                reward_percentiles,
                &mut working_set,
            )
            .map_err(to_eth_rpc_error)
    }

    // For account we return one of:
    //  - index_proof, 'n' (account_exists)
    //  - index_proof, index (little endian, 8 bytes), account_proof, 'y' (account_exists)
    //
    // For storages we return:
    //  value_proof, value_exists (y/n)
    fn eth_get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_id: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse> {
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());

        let evm = Evm::<C>::default();

        let block_id_internal = evm.block_number_from_state(block_id, &mut working_set)?;

        evm.set_state_to_end_of_evm_block_by_block_id(block_id, &mut working_set)?;

        let version = if block_id == Some(BlockId::Number(BlockNumberOrTag::Pending)) {
            // if pending it will already be last block + 1
            block_id_internal
        } else {
            block_id_internal
                .checked_add(1) // We need to set block_id to the end
                .ok_or_else(|| EthApiError::EvmCustom("Block id overflow".into()))?
        };

        let proof = generate_eth_proof(&evm, address, keys, version, &mut working_set);
        Ok(proof)
    }

    fn debug_trace_block_by_hash(
        &self,
        block_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>> {
        let evm = Evm::<C>::default();
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());

        let block_number = match evm.get_block_number_by_block_hash(block_hash, &mut working_set) {
            Some(block_number) => block_number,
            None => {
                return Err(EthApiError::HeaderNotFound(block_hash.into()).into());
            }
        };

        debug_trace_by_block_number(
            block_number,
            None,
            &self.ethereum,
            &evm,
            &mut working_set,
            opts,
        )
        .map_err(to_eth_rpc_error)
    }

    fn debug_trace_block_by_number(
        &self,
        block_number: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>> {
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());
        let evm = Evm::<C>::default();
        let latest_block_number: u64 = evm.block_number(&mut working_set)?.saturating_to();

        let block_number = match block_number {
            BlockNumberOrTag::Number(block_number) => block_number,
            BlockNumberOrTag::Latest => latest_block_number,
            _ => return Err(EthApiError::Unsupported(
                "Earliest, pending, safe and finalized are not supported for debug_traceBlockByNumber",
            ).into()),
        };

        debug_trace_by_block_number(
            block_number,
            None,
            &self.ethereum,
            &evm,
            &mut working_set,
            opts,
        )
        .map_err(to_eth_rpc_error)
    }

    // the main rpc handler for debug_traceTransaction
    // Checks the cache in ethereum struct if the trace exists
    // if found; returns the trace
    // else; calls the debug_trace_transaction_block function in evm
    // that function traces the entire block, returns all the traces to here
    // then we put them into cache and return the trace of the requested transaction
    fn debug_trace_transaction(
        &self,
        tx_hash: B256,
        opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<GethTrace> {
        let evm = Evm::<C>::default();
        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());

        let tx = evm
            .get_transaction_by_hash(tx_hash, &mut working_set)
            .unwrap()
            .ok_or_else(|| EthApiError::UnknownBlockOrTxIndex)?;

        let trace_idx: u64 = tx
            .transaction_index
            .expect("Tx index must be set for tx inside block");

        let block_number: u64 = tx
            .block_number
            .expect("Block number must be set for tx inside block");

        let traces = debug_trace_by_block_number(
            block_number,
            Some(trace_idx as usize),
            &self.ethereum,
            &evm,
            &mut working_set,
            opts,
        )
        .map_err(to_eth_rpc_error)?;

        match &traces[0] {
            TraceResult::Success { result, .. } => Ok(result.clone()),
            // this should never happen since we propagate any tracing error
            TraceResult::Error { error, tx_hash: _ } => {
                Err(EthApiError::EvmCustom(error.clone()).into())
            }
        }
    }

    fn txpool_content(&self) -> RpcResult<Value> {
        // This is a simple mock for serde.
        Ok(json!({
            "pending": {},
            "queued": {}
        }))
    }

    fn get_uncle_by_block_hash_and_index(
        &self,
        _block_hash: String,
        _uncle_index: String,
    ) -> RpcResult<Value> {
        Ok(json!(null))
    }

    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256> {
        self.ethereum
            .sequencer_client
            .as_ref()
            .unwrap()
            .eth_send_raw_transaction(data)
            .await
            .map_err(|e| match e {
                jsonrpsee::core::client::Error::Call(e_owned) => e_owned,
                _ => to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e),
            })
    }

    async fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>> {
        match mempool_only {
            Some(true) => {
                match self
                    .ethereum
                    .sequencer_client
                    .as_ref()
                    .unwrap()
                    .eth_get_transaction_by_hash(hash, Some(true))
                    .await
                {
                    Ok(tx) => Ok(tx),
                    Err(e) => match e {
                        jsonrpsee::core::client::Error::Call(e_owned) => Err(e_owned),
                        _ => Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
                    },
                }
            }
            _ => {
                let evm = Evm::<C>::default();
                let mut working_set = WorkingSet::new(self.ethereum.storage.clone());
                match evm.get_transaction_by_hash(hash, &mut working_set) {
                    Ok(Some(tx)) => Ok(Some(tx)),
                    Ok(None) => {
                        match self
                            .ethereum
                            .sequencer_client
                            .as_ref()
                            .unwrap()
                            .eth_get_transaction_by_hash(hash, Some(true))
                            .await
                        {
                            Ok(tx) => Ok(tx),
                            Err(e) => match e {
                                jsonrpsee::core::client::Error::Call(e_owned) => Err(e_owned),
                                _ => Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
                            },
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    async fn citrea_sync_status(&self) -> RpcResult<SyncStatus> {
        let (sequencer_response, da_response) = join!(
            self.ethereum
                .sequencer_client
                .as_ref()
                .unwrap()
                .get_head_l2_block_height(),
            self.ethereum.da_service.get_last_finalized_block_header()
        );

        let l2_head_block_number = match sequencer_response {
            Ok(block_number) => block_number,
            Err(e) => match e {
                jsonrpsee::core::client::Error::Call(e_owned) => return Err(e_owned),
                _ => return Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
            },
        };

        let head_l2_block = self.ethereum.ledger_db.get_head_l2_block();
        let l2_synced_block_number = match head_l2_block {
            Ok(Some((height, _))) => height.0,
            Ok(None) => 0u64,
            Err(e) => return Err(to_jsonrpsee_error_object("LEDGER_DB_ERROR", e)),
        };

        let l1_head_block_number = match da_response {
            Ok(header) => header.height(),
            Err(e) => return Err(to_jsonrpsee_error_object("DA_SERVICE_ERROR", e)),
        };

        let l1_synced_block_number = match self.ethereum.ledger_db.get_last_scanned_l1_height() {
            Ok(Some(slot_number)) => slot_number.0,
            Ok(None) => 0u64,
            Err(e) => return Err(to_jsonrpsee_error_object("LEDGER_DB_ERROR", e)),
        };

        let l1_status = if l1_synced_block_number < l1_head_block_number {
            LayerStatus::Syncing(SyncValues {
                synced_block_number: U64::from(l1_synced_block_number),
                head_block_number: U64::from(l1_head_block_number),
            })
        } else {
            LayerStatus::Synced(U64::from(l1_head_block_number))
        };

        let l2_status = if l2_synced_block_number < l2_head_block_number.to() {
            LayerStatus::Syncing(SyncValues {
                synced_block_number: U64::from(l2_synced_block_number),
                head_block_number: U64::from(l2_head_block_number),
            })
        } else {
            LayerStatus::Synced(U64::from(l2_head_block_number))
        };

        Ok(SyncStatus {
            l1_status,
            l2_status,
        })
    }

    async fn subscribe_debug(
        &self,
        pending: PendingSubscriptionSink,
        topic: String,
        start_block: BlockNumberOrTag,
        end_block: BlockNumberOrTag,
        opts: Option<GethDebugTracingOptions>,
    ) -> SubscriptionResult {
        if &topic == "traceChain" {
            handle_debug_trace_chain(start_block, end_block, opts, pending, self.ethereum.clone())
                .await;
        } else {
            pending
                .reject(to_eth_rpc_error("Unsupported subscription topic"))
                .await;
        }
        Ok(())
    }

    async fn subscribe_eth(
        &self,
        pending: PendingSubscriptionSink,
        topic: String,
        filter: Option<Filter>,
    ) -> SubscriptionResult {
        match topic.as_str() {
            "newHeads" => {
                let subscription = pending.accept().await?;
                self.ethereum
                    .subscription_manager
                    .as_ref()
                    .unwrap()
                    .register_new_heads_subscription(subscription)
                    .await;
            }
            "logs" => {
                let subscription = pending.accept().await?;
                self.ethereum
                    .subscription_manager
                    .as_ref()
                    .unwrap()
                    .register_new_logs_subscription(filter.unwrap_or_default(), subscription)
                    .await;
            }
            _ => {
                pending
                    .reject(EthApiError::Unsupported("Unsupported subscription topic"))
                    .await;
            }
        }
        Ok(())
    }
}

pub fn create_rpc_module<C, Da>(
    da_service: Arc<Da>,
    eth_rpc_config: EthRpcConfig,
    storage: C::Storage,
    ledger_db: LedgerDB,
    sequencer_client_url: Option<String>,
    l2_block_rx: Option<broadcast::Receiver<u64>>,
) -> RpcModule<EthereumRpcServerImpl<C, Da>>
where
    C: sov_modules_api::Context,
    C::Storage: NativeStorage,
    Da: DaService,
{
    // Unpack config
    let EthRpcConfig {
        gas_price_oracle_config,
        fee_history_cache_config,
    } = eth_rpc_config;

    // If the node does not have a sequencer client, then it is the sequencer.
    let is_sequencer = sequencer_client_url.is_none();
    let enable_subscriptions = l2_block_rx.is_some();

    // If the running node is a full node rpc context should also have sequencer client so that it can send txs to sequencer
    let ethereum = Arc::new(Ethereum::new(
        da_service,
        gas_price_oracle_config,
        fee_history_cache_config,
        storage,
        ledger_db,
        sequencer_client_url.map(|url| HttpClientBuilder::default().build(url).unwrap()),
        l2_block_rx,
    ));
    let server = EthereumRpcServerImpl::new(ethereum);

    let mut module = EthereumRpcServer::into_rpc(server);

    if is_sequencer {
        module.remove_method("eth_sendRawTransaction");
        module.remove_method("eth_getTransactionByHash");
        module.remove_method("citrea_syncStatus");
    }

    if !enable_subscriptions {
        module.remove_method("eth_subscribe");
        module.remove_method("eth_unsubscribe");
        module.remove_method("debug_subscribe");
        module.remove_method("debug_unsubscribe");
    }

    module
}
