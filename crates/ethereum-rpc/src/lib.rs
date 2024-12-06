mod ethereum;
mod gas_price;
mod subscription;
mod trace;

use std::sync::Arc;

#[cfg(feature = "local")]
pub use citrea_evm::DevSigner;
use citrea_evm::{Evm, Filter};
pub use ethereum::{EthRpcConfig, Ethereum};
pub use gas_price::fee_history::FeeHistoryCacheConfig;
pub use gas_price::gas_oracle::GasPriceOracleConfig;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::{keccak256, BlockNumberOrTag, Bytes, B256, U256};
use reth_rpc_eth_types::EthApiError;
use reth_rpc_types::trace::geth::{GethDebugTracingOptions, GethTrace};
use reth_rpc_types::{FeeHistory, Index};
use sequencer_client::SequencerClient;
use serde_json::json;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tokio::join;
use tokio::sync::broadcast;
use trace::{debug_trace_by_block_number, handle_debug_trace_chain};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncValues {
    pub head_block_number: u64,
    pub synced_block_number: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum LayerStatus {
    Synced(u64),
    Syncing(SyncValues),
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatus {
    pub l1_status: LayerStatus,
    pub l2_status: LayerStatus,
}

pub fn get_ethereum_rpc<C: sov_modules_api::Context, Da: DaService>(
    da_service: Arc<Da>,
    eth_rpc_config: EthRpcConfig,
    storage: C::Storage,
    ledger_db: LedgerDB,
    sequencer_client_url: Option<String>,
    soft_confirmation_rx: Option<broadcast::Receiver<u64>>,
) -> RpcModule<Ethereum<C, Da>> {
    // Unpack config
    let EthRpcConfig {
        #[cfg(feature = "local")]
        eth_signer,
        gas_price_oracle_config,
        fee_history_cache_config,
    } = eth_rpc_config;

    // If the node does not have a sequencer client, then it is the sequencer.
    let is_sequencer = sequencer_client_url.is_none();
    let enable_subscriptions = soft_confirmation_rx.is_some();

    // If the running node is a full node rpc context should also have sequencer client so that it can send txs to sequencer
    let mut rpc = RpcModule::new(Ethereum::new(
        da_service,
        gas_price_oracle_config,
        fee_history_cache_config,
        #[cfg(feature = "local")]
        eth_signer,
        storage,
        ledger_db,
        sequencer_client_url.map(SequencerClient::new),
        soft_confirmation_rx,
    ));

    register_rpc_methods(&mut rpc, is_sequencer, enable_subscriptions)
        .expect("Failed to register ethereum RPC methods");
    rpc
}

fn register_rpc_methods<C: sov_modules_api::Context, Da: DaService>(
    rpc: &mut RpcModule<Ethereum<C, Da>>,
    // Checks wether the running node is a sequencer or not, if it is not a sequencer it should also have methods like eth_sendRawTransaction here.
    is_sequencer: bool,
    enable_subscriptions: bool,
) -> Result<(), jsonrpsee::core::RegisterMethodError> {
    rpc.register_async_method("web3_clientVersion", |_, ethereum, _| async move {
        Ok::<_, ErrorObjectOwned>(ethereum.web3_client_version.clone())
    })?;

    rpc.register_blocking_method("web3_sha3", move |params, _, _| {
        let data: Bytes = params.one()?;

        let hash = B256::from_slice(keccak256(&data).as_slice());

        Ok::<_, ErrorObjectOwned>(hash)
    })?;

    rpc.register_blocking_method("eth_gasPrice", move |_, ethereum, _| {
        let price = {
            let mut working_set = WorkingSet::new(ethereum.storage.clone());

            let (base_fee, suggested_tip) = ethereum.max_fee_per_gas(&mut working_set);

            suggested_tip + base_fee
        };

        Ok::<U256, ErrorObjectOwned>(price)
    })?;

    rpc.register_blocking_method("eth_maxFeePerGas", move |_, ethereum, _| {
        let max_fee_per_gas = {
            let mut working_set = WorkingSet::new(ethereum.storage.clone());

            let (base_fee, suggested_tip) = ethereum.max_fee_per_gas(&mut working_set);

            suggested_tip + base_fee
        };

        Ok::<U256, ErrorObjectOwned>(max_fee_per_gas)
    })?;

    rpc.register_blocking_method("eth_maxPriorityFeePerGas", move |_, ethereum, _| {
        let max_priority_fee = {
            let mut working_set = WorkingSet::new(ethereum.storage.clone());

            let (_base_fee, suggested_tip) = ethereum.max_fee_per_gas(&mut working_set);

            suggested_tip
        };

        Ok::<U256, ErrorObjectOwned>(max_priority_fee)
    })?;

    rpc.register_blocking_method("eth_feeHistory", move |params, ethereum, _| {
        let mut params = params.sequence();

        let block_count: Index = params.next()?;
        let newest_block: BlockNumberOrTag = params.next()?;
        let reward_percentiles: Option<Vec<f64>> = params.optional_next()?;

        // convert block count to u64 from hex
        let block_count = usize::from(block_count) as u64;

        let fee_history = {
            let mut working_set = WorkingSet::new(ethereum.storage.clone());

            ethereum.gas_price_oracle.fee_history(
                block_count,
                newest_block,
                reward_percentiles,
                &mut working_set,
            )?
        };

        Ok::<FeeHistory, ErrorObjectOwned>(fee_history)
    })?;

    #[cfg(feature = "local")]
    rpc.register_async_method("eth_accounts", |_, ethereum, _| async move {
        Ok::<_, ErrorObjectOwned>(ethereum.eth_signer.signers())
    })?;

    // #[cfg(feature = "local")]
    // rpc.register_async_method("eth_sendTransaction", |parameters, ethereum| async move {
    //     let mut transaction_request: TransactionRequest = parameters.one().unwrap();

    //     let evm = Evm::<C>::default();

    //     // get from, return error if none
    //     let from = transaction_request
    //         .from
    //         .ok_or(to_jsonrpsee_error_object("No from address", ETH_RPC_ERROR))?;

    //     // return error if not in signers
    //     if !ethereum.eth_signer.signers().contains(&from) {
    //         return Err(to_jsonrpsee_error_object(
    //             "From address not in signers",
    //             ETH_RPC_ERROR,
    //         ));
    //     }

    //     let raw_evm_tx = {
    //         let mut working_set = WorkingSet::new(ethereum.storage.clone());

    //         // set nonce if none
    //         if transaction_request.nonce.is_none() {
    //             let nonce = evm
    //                 .get_transaction_count(from, None, &mut working_set)
    //                 .unwrap_or_default();

    //             transaction_request.nonce = Some(nonce);
    //         }

    //         // get current chain id
    //         let chain_id = evm
    //             .chain_id(&mut working_set)
    //             .expect("Failed to get chain id")
    //             .map(|id| id.to::<u64>())
    //             .unwrap_or(1);

    //         // get call request to estimate gas and gas prices
    //         let (call_request, _gas_price, _max_fee_per_gas) =
    //             get_call_request_and_params(from, chain_id, &transaction_request);

    //         // estimate gas limit
    //         let gas_limit = U256::from(
    //             evm.eth_estimate_gas(call_request, None, &mut working_set)?
    //                 .to::<u64>(),
    //         );

    //         let TransactionRequest {
    //             to,
    //             gas_price,
    //             max_fee_per_gas,
    //             max_priority_fee_per_gas,
    //             gas,
    //             value,
    //             input: data,
    //             nonce,
    //             mut access_list,
    //             max_fee_per_blob_gas,
    //             blob_versioned_hashes,
    //             sidecar,
    //             ..
    //         } = transaction_request;

    //         // todo: remove this inlining after https://github.com/alloy-rs/alloy/pull/183#issuecomment-1928161285
    //         let transaction = match (
    //             gas_price,
    //             max_fee_per_gas,
    //             access_list.take(),
    //             max_fee_per_blob_gas,
    //             blob_versioned_hashes,
    //             sidecar,
    //         ) {
    //             // legacy transaction
    //             // gas price required
    //             (Some(_), None, None, None, None, None) => {
    //                 Some(TypedTransactionRequest::Legacy(LegacyTransactionRequest {
    //                     nonce: nonce.unwrap_or_default(),
    //                     gas_price: gas_price.unwrap_or_default(),
    //                     gas_limit: gas.unwrap_or_default(),
    //                     value: value.unwrap_or_default(),
    //                     input: data.into_input().unwrap_or_default(),
    //                     kind: match to {
    //                         Some(to) => RpcTransactionKind::Call(to),
    //                         None => RpcTransactionKind::Create,
    //                     },
    //                     chain_id: None,
    //                 }))
    //             }
    //             // EIP2930
    //             // if only accesslist is set, and no eip1599 fees
    //             (_, None, Some(access_list), None, None, None) => Some(
    //                 TypedTransactionRequest::EIP2930(EIP2930TransactionRequest {
    //                     nonce: nonce.unwrap_or_default(),
    //                     gas_price: gas_price.unwrap_or_default(),
    //                     gas_limit: gas.unwrap_or_default(),
    //                     value: value.unwrap_or_default(),
    //                     input: data.into_input().unwrap_or_default(),
    //                     kind: match to {
    //                         Some(to) => RpcTransactionKind::Call(to),
    //                         None => RpcTransactionKind::Create,
    //                     },
    //                     chain_id: 0,
    //                     access_list,
    //                 }),
    //             ),
    //             // EIP1559
    //             // if 4844 fields missing
    //             // gas_price, max_fee_per_gas, access_list, max_fee_per_blob_gas, blob_versioned_hashes,
    //             // sidecar,
    //             (None, _, _, None, None, None) => {
    //                 // Empty fields fall back to the canonical transaction schema.
    //                 Some(TypedTransactionRequest::EIP1559(
    //                     EIP1559TransactionRequest {
    //                         nonce: nonce.unwrap_or_default(),
    //                         max_fee_per_gas: max_fee_per_gas.unwrap_or_default(),
    //                         max_priority_fee_per_gas: max_priority_fee_per_gas.unwrap_or_default(),
    //                         gas_limit: gas.unwrap_or_default(),
    //                         value: value.unwrap_or_default(),
    //                         input: data.into_input().unwrap_or_default(),
    //                         kind: match to {
    //                             Some(to) => RpcTransactionKind::Call(to),
    //                             None => RpcTransactionKind::Create,
    //                         },
    //                         chain_id: 0,
    //                         access_list: access_list.unwrap_or_default(),
    //                     },
    //                 ))
    //             }
    //             // EIP4884
    //             // all blob fields required
    //             (
    //                 None,
    //                 _,
    //                 _,
    //                 Some(max_fee_per_blob_gas),
    //                 Some(blob_versioned_hashes),
    //                 Some(sidecar),
    //             ) => {
    //                 // As per the EIP, we follow the same semantics as EIP-1559.
    //                 Some(TypedTransactionRequest::EIP4844(
    //                     EIP4844TransactionRequest {
    //                         chain_id: 0,
    //                         nonce: nonce.unwrap_or_default(),
    //                         max_priority_fee_per_gas: max_priority_fee_per_gas.unwrap_or_default(),
    //                         max_fee_per_gas: max_fee_per_gas.unwrap_or_default(),
    //                         gas_limit: gas.unwrap_or_default(),
    //                         value: value.unwrap_or_default(),
    //                         input: data.into_input().unwrap_or_default(),
    //                         kind: match to {
    //                             Some(to) => RpcTransactionKind::Call(to),
    //                             None => RpcTransactionKind::Create,
    //                         },
    //                         access_list: access_list.unwrap_or_default(),

    //                         // eip-4844 specific.
    //                         max_fee_per_blob_gas,
    //                         blob_versioned_hashes,
    //                         sidecar,
    //                     },
    //                 ))
    //             }

    //             _ => None,
    //         };

    //         // get typed transaction request
    //         let transaction_request = match transaction {
    //             Some(TypedTransactionRequest::Legacy(mut m)) => {
    //                 m.chain_id = Some(chain_id);
    //                 m.gas_limit = gas_limit;
    //                 m.gas_price = gas_price.unwrap();

    //                 TypedTransactionRequest::Legacy(m)
    //             }
    //             Some(TypedTransactionRequest::EIP2930(mut m)) => {
    //                 m.chain_id = chain_id;
    //                 m.gas_limit = gas_limit;
    //                 m.gas_price = gas_price.unwrap();

    //                 TypedTransactionRequest::EIP2930(m)
    //             }
    //             Some(TypedTransactionRequest::EIP1559(mut m)) => {
    //                 m.chain_id = chain_id;
    //                 m.gas_limit = gas_limit;
    //                 m.max_fee_per_gas = max_fee_per_gas.unwrap();

    //                 TypedTransactionRequest::EIP1559(m)
    //             }
    //             Some(TypedTransactionRequest::EIP4844(mut m)) => {
    //                 m.chain_id = chain_id;
    //                 m.gas_limit = gas_limit;
    //                 m.max_fee_per_gas = max_fee_per_gas.unwrap();

    //                 TypedTransactionRequest::EIP4844(m)
    //             }
    //             None => return Err(EthApiError::ConflictingFeeFieldsInRequest.into()),
    //         };

    //         // get raw transaction
    //         let transaction = to_primitive_transaction(transaction_request)
    //             .ok_or(SignError::InvalidTransactionRequest)?;

    //         // sign transaction
    //         let signed_tx = ethereum
    //             .eth_signer
    //             .sign_transaction(transaction, from)
    //             .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

    //         RlpEvmTransaction {
    //             rlp: signed_tx.envelope_encoded().to_vec(),
    //         }
    //     };
    //     let (tx_hash, raw_message) = ethereum
    //         .make_raw_tx(raw_evm_tx)
    //         .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

    //     ethereum.add_messages(vec![raw_message]);

    //     Ok::<_, ErrorObjectOwned>(tx_hash)
    // })?;

    rpc.register_blocking_method::<Result<Vec<GethTrace>, ErrorObjectOwned>, _>(
        "debug_traceBlockByHash",
        move |parameters, ethereum, _| {
            let mut params = parameters.sequence();

            let block_hash: B256 = params.next()?;
            let evm = Evm::<C>::default();
            let mut working_set = WorkingSet::new(ethereum.storage.clone());
            let opts: Option<GethDebugTracingOptions> = params.optional_next()?;

            let block_number =
                match evm.get_block_number_by_block_hash(block_hash, &mut working_set) {
                    Some(block_number) => block_number,
                    None => {
                        return Err(EthApiError::UnknownBlockNumber.into());
                    }
                };

            debug_trace_by_block_number(block_number, None, &ethereum, &evm, &mut working_set, opts)
        },
    )?;

    rpc.register_blocking_method::<Result<Vec<GethTrace>, ErrorObjectOwned>, _>(
        "debug_traceBlockByNumber",
        move |parameters, ethereum, _| {
            let mut params = parameters.sequence();

            let block_number: BlockNumberOrTag = params.next()?;
            let opts: Option<GethDebugTracingOptions> = params.optional_next()?;

            let mut working_set = WorkingSet::new(ethereum.storage.clone());
            let evm = Evm::<C>::default();
            let latest_block_number: u64 = evm.block_number(&mut working_set)?.saturating_to();

            let block_number = match block_number {
                BlockNumberOrTag::Number(block_number) => block_number,
                BlockNumberOrTag::Latest => latest_block_number,
                _ => return Err(EthApiError::Unsupported(
                    "Earliest, pending, safe and finalized are not supported for debug_traceBlockByNumber",
                )
                .into()),
            };

            debug_trace_by_block_number(block_number, None, &ethereum, &evm, &mut working_set, opts)
        },
    )?;

    rpc.register_blocking_method::<Result<GethTrace, ErrorObjectOwned>, _>(
        "debug_traceTransaction",
        move |parameters, ethereum, _| {
            // the main rpc handler for debug_traceTransaction
            // Checks the cache in ethereum struct if the trace exists
            // if found; returns the trace
            // else; calls the debug_trace_transaction_block function in evm
            // that function traces the entire block, returns all the traces to here
            // then we put them into cache and return the trace of the requested transaction
            let mut params = parameters.sequence();

            let tx_hash: B256 = params.next()?;

            let evm = Evm::<C>::default();
            let mut working_set = WorkingSet::new(ethereum.storage.clone());

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

            let opts: Option<GethDebugTracingOptions> = params.optional_next()?;

            let traces = debug_trace_by_block_number(
                block_number,
                Some(trace_idx as usize),
                &ethereum,
                &evm,
                &mut working_set,
                opts,
            )?;
            Ok(traces[0].clone())
        },
    )?;

    rpc.register_async_method("txpool_content", |_, _, _| async move {
        // This is a simple mock for serde.
        let json = json!({
            "pending": {},
            "queued": {}
        });

        Ok::<_, ErrorObjectOwned>(json)
    })?;

    rpc.register_async_method(
        "eth_getUncleByBlockHashAndIndex",
        |parameters, _, _| async move {
            let mut params = parameters.sequence();

            let _block_hash: String = params.next()?;
            let _uncle_index_position: String = params.next()?;

            let res = json!(null);

            Ok::<_, ErrorObjectOwned>(res)
        },
    )?;

    if !is_sequencer {
        rpc.register_async_method::<Result<B256, ErrorObjectOwned>, _, _>(
            "eth_sendRawTransaction",
            |parameters, ethereum, _| async move {
                // send this directly to the sequencer
                let data: Bytes = parameters.one()?;
                // sequencer client should send it
                let tx_hash = ethereum
                    .sequencer_client
                    .as_ref()
                    .unwrap()
                    .send_raw_tx(data)
                    .await;

                match tx_hash {
                    Ok(tx_hash) => Ok(tx_hash),
                    Err(e) => match e {
                        jsonrpsee::core::client::Error::Call(e_owned) => Err(e_owned),
                        _ => Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
                    },
                }
            },
        )?;

        rpc.register_async_method::<Result<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>, _, _>(
            "eth_getTransactionByHash",
            |parameters, ethereum, _| async move {
                let mut params = parameters.sequence();
                let hash: B256 = params.next()?;
                let mempool_only: Result<Option<bool>, ErrorObjectOwned> = params.optional_next();

                // check if mempool_only parameter was given what was its value
                match mempool_only {
                    // only ask sequencer
                    Ok(Some(true)) => {
                        match ethereum
                            .sequencer_client
                            .as_ref()
                            .unwrap()
                            .get_tx_by_hash(hash, Some(true))
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
                        // if mempool_only is not true ask evm first then sequencer
                        let evm = Evm::<C>::default();
                        let mut working_set = WorkingSet::new(ethereum.storage.clone());
                        match evm.get_transaction_by_hash(hash, &mut working_set) {
                            Ok(Some(tx)) => Ok(Some(tx)),
                            Ok(None) => {
                                // if not found in evm then ask to sequencer mempool
                                match ethereum
                                    .sequencer_client
                                    .as_ref()
                                    .unwrap()
                                    .get_tx_by_hash(hash, Some(true))
                                    .await
                                {
                                    Ok(tx) => Ok(tx),
                                    Err(e) => match e {
                                        jsonrpsee::core::client::Error::Call(e_owned) => Err(e_owned),
                                        _ => Err(to_jsonrpsee_error_object(
                                            "SEQUENCER_CLIENT_ERROR",
                                            e,
                                        )),
                                    },
                                }
                            }
                            Err(e) => {
                                // return error
                                Err(e)
                            }
                        }
                    }
                }
            },
        )?;

        rpc.register_async_method::<Result<SyncStatus, ErrorObjectOwned>, _, _>(
            "citrea_syncStatus",
            |_, ethereum, _| async move {
                // sequencer client should send latest l2 height
                // da service should send latest finalized l1 block header
                let (sequencer_response, da_response) = join!(
                    ethereum.sequencer_client.as_ref().unwrap().block_number(),
                    ethereum.da_service.get_last_finalized_block_header()
                );
                // handle sequencer response
                let l2_head_block_number = match sequencer_response {
                    Ok(block_number) => block_number,
                    Err(e) => match e {
                        jsonrpsee::core::client::Error::Call(e_owned) => return Err(e_owned),
                        _ => return Err(to_jsonrpsee_error_object("SEQUENCER_CLIENT_ERROR", e)),
                    },
                };

                // get l2 synced block number

                let head_soft_confirmation = ethereum.ledger_db.get_head_soft_confirmation();

                let l2_synced_block_number = match head_soft_confirmation {
                    Ok(Some((height, _))) => height.0,
                    Ok(None) => 0u64,
                    Err(e) => return Err(to_jsonrpsee_error_object("LEDGER_DB_ERROR", e)),
                };

                // handle da service response
                let l1_head_block_number = match da_response {
                    Ok(header) => header.height(),
                    Err(e) => return Err(to_jsonrpsee_error_object("DA_SERVICE_ERROR", e)),
                };

                // get l1 synced block number
                let l1_synced_block_number = match ethereum.ledger_db.get_last_scanned_l1_height() {
                    Ok(Some(slot_number)) => slot_number.0,
                    Ok(None) => 0u64,
                    Err(e) => return Err(to_jsonrpsee_error_object("LEDGER_DB_ERROR", e)),
                };

                let l1_status = if l1_synced_block_number < l1_head_block_number {
                    LayerStatus::Syncing(SyncValues {
                        synced_block_number: l1_synced_block_number,
                        head_block_number: l1_head_block_number,
                    })
                } else {
                    LayerStatus::Synced(l1_head_block_number)
                };
                let l2_status = if l2_synced_block_number < l2_head_block_number {
                    LayerStatus::Syncing(SyncValues {
                        synced_block_number: l2_synced_block_number,
                        head_block_number: l2_head_block_number,
                    })
                } else {
                    LayerStatus::Synced(l2_head_block_number)
                };
                Ok::<SyncStatus, ErrorObjectOwned>(SyncStatus {
                    l1_status,
                    l2_status,
                })
            },
        )?;
    }

    if enable_subscriptions {
        rpc.register_subscription(
            "debug_subscribe",
            "debug_subscription",
            "debug_unsubscribe",
            |parameters, pending, ethereum, _| async move {
                let mut params = parameters.sequence();

                let topic: String = match params.next() {
                    Ok(v) => v,
                    Err(err) => {
                        pending.reject(err).await;
                        return Ok(());
                    }
                };
                match topic.as_str() {
                    "traceChain" => handle_debug_trace_chain(params, pending, ethereum).await,
                    _ => {
                        pending
                            .reject(EthApiError::Unsupported("Unsupported subscription topic"))
                            .await;
                        return Ok(());
                    }
                };

                Ok(())
            },
        )?;

        rpc.register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |parameters, pending, ethereum, _| async move {
                let mut params = parameters.sequence();

                let topic: String = match params.next() {
                    Ok(v) => v,
                    Err(err) => {
                        pending.reject(err).await;
                        return Ok(());
                    }
                };
                match topic.as_str() {
                    "newHeads" => {
                        let subscription = pending.accept().await.unwrap();
                        ethereum
                            .subscription_manager
                            .as_ref()
                            .unwrap()
                            .register_new_heads_subscription(subscription)
                            .await;
                    }
                    "logs" => {
                        let filter: Filter = match params.next() {
                            Ok(v) => v,
                            Err(err) => {
                                pending.reject(err).await;
                                return Ok(());
                            }
                        };
                        let subscription = pending.accept().await.unwrap();
                        ethereum
                            .subscription_manager
                            .as_ref()
                            .unwrap()
                            .register_new_logs_subscription(filter, subscription)
                            .await;
                    }
                    _ => {
                        pending
                            .reject(EthApiError::Unsupported("Unsupported subscription topic"))
                            .await;
                        return Ok(());
                    }
                };

                Ok(())
            },
        )?;
    }

    Ok(())
}

// fn get_call_request_and_params(
//     from: Address,
//     chain_id: u64,
//     request: &TransactionRequest,
// ) -> (TransactionRequest, U256, U256) {
//     // TODO: we need an oracle to fetch the gas price of the current chain
//     // https://github.com/Sovereign-Labs/sovereign-sdk/issues/883
//     let gas_price = request.gas_price.unwrap_or_default();
//     let max_fee_per_gas = request.max_fee_per_gas.unwrap_or_default();

//     // TODO: Generate call request better according to the transaction type
//     // https://github.com/Sovereign-Labs/sovereign-sdk/issues/946
//     let call_request = TransactionRequest {
//         from: Some(from),
//         to: request.to,
//         gas: request.gas,
//         gas_price: Some(U256::from(gas_price)),
//         max_fee_per_gas: Some(U256::from(max_fee_per_gas)),
//         value: request.value,
//         input: request.input.clone(),
//         nonce: request.nonce,
//         chain_id: Some(U64::from(chain_id)),
//         access_list: request.access_list.clone(),
//         max_priority_fee_per_gas: Some(U256::from(max_fee_per_gas)),
//         transaction_type: None,
//         blob_versioned_hashes: None,
//         max_fee_per_blob_gas: None,
//         sidecar: None,
//         other: OtherFields::default(),
//     };

//     (call_request, gas_price, max_fee_per_gas)
// }
