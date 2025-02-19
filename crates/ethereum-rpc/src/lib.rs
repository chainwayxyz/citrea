mod ethereum;
mod gas_price;
mod subscription;
mod trace;

use std::sync::Arc;

use alloy_network::AnyNetwork;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256, U64};
use alloy_rpc_types::serde_helpers::JsonStorageKey;
use alloy_rpc_types::{EIP1186AccountProofResponse, EIP1186StorageProof, FeeHistory, Index};
use alloy_rpc_types_trace::geth::{GethDebugTracingOptions, GethTrace, TraceResult};
use citrea_evm::{DbAccount, Evm, Filter};
use citrea_primitives::forks::fork_from_block_number;
use citrea_sequencer::SequencerRpcClient;
pub use ethereum::{EthRpcConfig, Ethereum};
pub use gas_price::fee_history::FeeHistoryCacheConfig;
pub use gas_price::gas_oracle::GasPriceOracleConfig;
use jsonrpsee::core::{RpcResult, SubscriptionResult};
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{PendingSubscriptionSink, RpcModule};
use reth_primitives::{BlockId, BlockNumberOrTag, KECCAK_EMPTY};
use reth_rpc_eth_api::RpcTransaction;
use reth_rpc_eth_types::EthApiError;
use serde_json::{json, Value};
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::{SpecId as CitreaSpecId, StateMapAccessor, WorkingSet};
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
    ) -> RpcResult<Option<RpcTransaction<AnyNetwork>>>;

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

    // For account for fork1 we return:
    //  fork1, account_proof, account_exists (y/n)
    // For account for fork2 we return one of:
    //  - fork2, index_proof, n
    //  - fork2, index_proof, index (little endian, 8 bytes), account_proof, account_exists (y)
    //
    // For storages we return:
    //  fork1/fork2, value_proof, value_exists (y/n)
    fn eth_get_proof(
        &self,
        address: Address,
        keys: Vec<JsonStorageKey>,
        block_id: Option<BlockId>,
    ) -> RpcResult<EIP1186AccountProofResponse> {
        use sov_state::storage::{StateCodec, StorageKey};

        let mut working_set = WorkingSet::new(self.ethereum.storage.clone());

        let evm = Evm::<C>::default();

        let block_id_internal = evm.block_number_from_state(block_id, &mut working_set)?;

        let citrea_spec = fork_from_block_number(block_id_internal).spec_id;

        evm.set_state_to_end_of_evm_block_by_block_id(block_id, &mut working_set)?;

        let version = if block_id == Some(BlockId::Number(BlockNumberOrTag::Pending)) {
            // if pending it will already be last block + 1
            block_id_internal
        } else {
            block_id_internal
                .checked_add(1) // We need to set block_id to the end
                .ok_or_else(|| EthApiError::EvmCustom("Block id overflow".into()))?
        };

        let root_hash = working_set
            .get_root_hash(version)
            .map_err(|_| EthApiError::EvmCustom("Root hash not found".into()))?;

        let account_in_fork1 = evm.account_info_prefork2(&address, &mut working_set);
        let account_in_fork2 = evm.account_info_postfork2(&address, &mut working_set);
        let account_should_gen_prefork2_proof = citrea_spec < CitreaSpecId::Fork2
            || (account_in_fork1.is_some() && account_in_fork2.is_none());

        let account = if account_should_gen_prefork2_proof {
            account_in_fork1.unwrap_or_default()
        } else {
            account_in_fork2.unwrap_or_default()
        };
        let balance = account.balance;
        let nonce = account.nonce;
        let code_hash = account.code_hash.unwrap_or(KECCAK_EMPTY);

        // Remove before mainet
        fn generate_account_proof_prefork2<C>(
            evm: &Evm<C>,
            account: &Address,
            version: u64,
            working_set: &mut WorkingSet<C::Storage>,
        ) -> Vec<Bytes>
        where
            C: sov_modules_api::Context,
            C::Storage: NativeStorage,
        {
            let account_key = StorageKey::new(
                evm.accounts_prefork2.prefix(),
                &account,
                evm.accounts_prefork2.codec().key_codec(),
            );

            let account_proof = working_set.get_with_proof(account_key, version);
            let fork = Bytes::from("fork1"); // Remove before mainet
            let account_exists = if account_proof.value.is_some() {
                Bytes::from("y")
            } else {
                Bytes::from("n")
            };
            let account_proof =
                borsh::to_vec(&account_proof.proof).expect("Serialization shouldn't fail");
            let account_proof = Bytes::from(account_proof);
            vec![fork, account_proof, account_exists]
        }

        fn generate_account_proof_postfork2<C>(
            evm: &Evm<C>,
            account: &Address,
            version: u64,
            working_set: &mut WorkingSet<C::Storage>,
        ) -> Vec<Bytes>
        where
            C: sov_modules_api::Context,
            C::Storage: NativeStorage,
        {
            let fork = Bytes::from("fork2"); // Remove before mainet

            let index_key = StorageKey::new(
                evm.account_idxs.prefix(),
                &account,
                evm.account_idxs.codec().key_codec(),
            );
            let index_proof = working_set.get_with_proof(index_key, version);
            let index_proof_exists = index_proof.value.is_some();
            let index_proof =
                borsh::to_vec(&index_proof.proof).expect("Serialization shouldn't fail");
            let index_proof = Bytes::from(index_proof);

            if index_proof_exists {
                // we have to generate another proof for idx -> account
                let index = evm
                    .account_idxs
                    .get(account, working_set)
                    .expect("Account index exists");
                let index_bytes = Bytes::from_iter(index.to_le_bytes());

                let account_key = StorageKey::new(
                    evm.accounts_postfork2.prefix(),
                    &index,
                    evm.accounts_postfork2.codec().key_codec(),
                );

                let account_proof = working_set.get_with_proof(account_key, version);
                let account_exists = if account_proof.value.is_some() {
                    Bytes::from("y")
                } else {
                    Bytes::from("n")
                };
                let account_proof =
                    borsh::to_vec(&account_proof.proof).expect("Serialization shouldn't fail");
                let account_proof = Bytes::from(account_proof);
                vec![
                    fork,
                    index_proof,
                    index_bytes,
                    account_proof,
                    account_exists,
                ]
            } else {
                let index_exists = Bytes::from("n");

                vec![fork, index_proof, index_exists]
            }
        }

        // Remove before mainet
        fn generate_storage_proof_prefork2<C>(
            evm: &Evm<C>,
            account: &Address,
            key: &U256,
            citrea_spec: CitreaSpecId,
            version: u64,
            working_set: &mut WorkingSet<C::Storage>,
        ) -> EIP1186StorageProof
        where
            C: sov_modules_api::Context,
            C::Storage: NativeStorage,
        {
            let db_account = DbAccount::new(account);
            let storage_key = StorageKey::new(
                db_account.storage.prefix(),
                key,
                evm.storage.codec().key_codec(),
            );
            let value = evm.storage_get(account, key, citrea_spec, working_set);
            let proof = working_set.get_with_proof(storage_key, version);
            let fork = Bytes::from("fork1"); // Remove before mainet
            let value_exists = if proof.value.is_some() {
                Bytes::from("y")
            } else {
                Bytes::from("n")
            };
            let value_proof = borsh::to_vec(&proof.proof).expect("Serialization shouldn't fail");
            let value_proof = Bytes::from(value_proof);
            EIP1186StorageProof {
                key: JsonStorageKey(key.to_le_bytes().into()),
                value: value.unwrap_or_default(),
                proof: vec![fork, value_proof, value_exists],
            }
        }

        fn generate_storage_proof_postfork2<C>(
            evm: &Evm<C>,
            account: &Address,
            key: &U256,
            citrea_spec: CitreaSpecId,
            version: u64,
            working_set: &mut WorkingSet<C::Storage>,
        ) -> EIP1186StorageProof
        where
            C: sov_modules_api::Context,
            C::Storage: NativeStorage,
        {
            let kaddr = Evm::<C>::get_storage_address(account, key);
            let storage_key = StorageKey::new(
                evm.storage.prefix(),
                &kaddr,
                evm.storage.codec().key_codec(),
            );
            let value = evm.storage_get(account, key, citrea_spec, working_set);
            let proof = working_set.get_with_proof(storage_key, version);
            let fork = Bytes::from("fork2"); // Remove before mainet
            let value_exists = if proof.value.is_some() {
                Bytes::from("y")
            } else {
                Bytes::from("n")
            };
            let value_proof = borsh::to_vec(&proof.proof).expect("Serialization shouldn't fail");
            let value_proof = Bytes::from(value_proof);
            EIP1186StorageProof {
                key: JsonStorageKey(key.to_le_bytes().into()),
                value: value.unwrap_or_default(),
                proof: vec![fork, value_proof, value_exists],
            }
        }

        let account_proof = if account_should_gen_prefork2_proof {
            generate_account_proof_prefork2(&evm, &address, version, &mut working_set)
        } else {
            generate_account_proof_postfork2(&evm, &address, version, &mut working_set)
        };

        let mut storage_proof = vec![];
        for key in keys {
            let key: U256 = key.0.into();
            let in_fork1 = evm
                .storage_get_prefork2(&address, &key, &mut working_set)
                .is_some();
            let in_fork2 = evm
                .storage_get_postfork2(&address, &key, &mut working_set)
                .is_some();
            let should_gen_prefork2_proof =
                citrea_spec < CitreaSpecId::Fork2 || (in_fork1 && !in_fork2);
            let proof = if should_gen_prefork2_proof {
                generate_storage_proof_prefork2(
                    &evm,
                    &address,
                    &key,
                    citrea_spec,
                    version,
                    &mut working_set,
                )
            } else {
                generate_storage_proof_postfork2(
                    &evm,
                    &address,
                    &key,
                    citrea_spec,
                    version,
                    &mut working_set,
                )
            };
            storage_proof.push(proof);
        }

        Ok(EIP1186AccountProofResponse {
            address,
            balance,
            nonce,
            code_hash,
            storage_hash: root_hash.into(),
            account_proof,
            storage_proof,
        })
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
    ) -> RpcResult<Option<RpcTransaction<AnyNetwork>>> {
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
                .get_head_soft_confirmation_height(),
            self.ethereum.da_service.get_last_finalized_block_header()
        );

        let l2_head_block_number = match sequencer_response {
            Ok(block_number) => block_number,
            Err(e) => match e {
                jsonrpsee::core::client::Error::Call(e_owned) => return Err(e_owned),
                _ => return Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
            },
        };

        let head_soft_confirmation = self.ethereum.ledger_db.get_head_soft_confirmation();
        let l2_synced_block_number = match head_soft_confirmation {
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
    soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
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
    let enable_subscriptions = soft_confirmation_rx.is_some();

    // If the running node is a full node rpc context should also have sequencer client so that it can send txs to sequencer
    let ethereum = Arc::new(Ethereum::new(
        da_service,
        gas_price_oracle_config,
        fee_history_cache_config,
        storage,
        ledger_db,
        sequencer_client_url.map(|url| HttpClientBuilder::default().build(url).unwrap()),
        soft_confirmation_rx,
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
