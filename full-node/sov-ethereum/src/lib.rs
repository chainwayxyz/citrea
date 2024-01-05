mod batch_builder;
mod gas_price;
use std::array::TryFromSliceError;
use std::process::Command;
use std::sync::{Arc, Mutex};

use demo_stf::runtime::Runtime;
use ethers::types::{Bytes, H256};
pub use gas_price::fee_history::FeeHistoryCacheConfig;
use gas_price::gas_oracle::GasPriceOracle;
pub use gas_price::gas_oracle::GasPriceOracleConfig;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::rpc_utils::keccak256;
use reth_primitives::{
    BlockNumberOrTag, TransactionSignedNoHash as RethTransactionSignedNoHash, U128, U256,
};
use reth_rpc_types::{CallRequest, FeeHistory, TransactionRequest, TypedTransactionRequest};
use rustc_version_runtime::version;
use sequencer_client::SequencerClient;
#[cfg(feature = "local")]
pub use sov_evm::DevSigner;
use sov_evm::{CallMessage, Evm, RlpEvmTransaction};
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::{EncodeCall, PrivateKey, WorkingSet};
use sov_rollup_interface::services::da::DaService;
use tracing::info;

use crate::batch_builder::EthBatchBuilder;

const ETH_RPC_ERROR: &str = "ETH_RPC_ERROR";

#[derive(Clone)]
pub struct EthRpcConfig<C: sov_modules_api::Context> {
    pub min_blob_size: Option<usize>,
    pub sov_tx_signer_priv_key: C::PrivateKey,
    pub gas_price_oracle_config: GasPriceOracleConfig,
    pub fee_history_cache_config: FeeHistoryCacheConfig,
    #[cfg(feature = "local")]
    pub eth_signer: DevSigner,
}

pub fn get_ethereum_rpc<C: sov_modules_api::Context, Da: DaService>(
    da_service: Da,
    eth_rpc_config: EthRpcConfig<C>,
    storage: C::Storage,
    sequencer_client: Option<SequencerClient>,
) -> RpcModule<Ethereum<C, Da>> {
    // Unpack config
    let EthRpcConfig {
        min_blob_size,
        sov_tx_signer_priv_key,
        #[cfg(feature = "local")]
        eth_signer,
        gas_price_oracle_config,
        fee_history_cache_config,
    } = eth_rpc_config;

    // Fetch nonce from storage
    let accounts = sov_accounts::Accounts::<C>::default();
    let sov_tx_signer_account = accounts
        .get_account(
            sov_tx_signer_priv_key.pub_key(),
            &mut WorkingSet::<C>::new(storage.clone()),
        )
        .unwrap();
    let sov_tx_signer_nonce: u64 = match sov_tx_signer_account {
        sov_accounts::Response::AccountExists { nonce, .. } => nonce,
        sov_accounts::Response::AccountEmpty { .. } => 0,
    };
    // If the node does not have a sequencer client, then it is the sequencer.
    let is_sequencer = sequencer_client.is_none();

    // If the running node is a full node rpc context should also have sequencer client so that it can send txs to sequencer
    let mut rpc = RpcModule::new(Ethereum::new(
        da_service,
        Arc::new(Mutex::new(EthBatchBuilder::new(
            sov_tx_signer_priv_key,
            sov_tx_signer_nonce,
            min_blob_size,
        ))),
        gas_price_oracle_config,
        fee_history_cache_config,
        #[cfg(feature = "local")]
        eth_signer,
        storage,
        sequencer_client,
    ));

    register_rpc_methods(&mut rpc, is_sequencer).expect("Failed to register sequencer RPC methods");
    rpc
}

pub struct Ethereum<C: sov_modules_api::Context, Da: DaService> {
    #[allow(dead_code)]
    da_service: Da,
    batch_builder: Arc<Mutex<EthBatchBuilder<C>>>,
    gas_price_oracle: GasPriceOracle<C>,
    #[cfg(feature = "local")]
    eth_signer: DevSigner,
    storage: C::Storage,
    sequencer_client: Option<SequencerClient>,
    web3_client_version: String,
}

impl<C: sov_modules_api::Context, Da: DaService> Ethereum<C, Da> {
    fn new(
        da_service: Da,
        batch_builder: Arc<Mutex<EthBatchBuilder<C>>>,
        gas_price_oracle_config: GasPriceOracleConfig,
        fee_history_cache_config: FeeHistoryCacheConfig,
        #[cfg(feature = "local")] eth_signer: DevSigner,
        storage: C::Storage,
        sequencer_client: Option<SequencerClient>,
    ) -> Self {
        let evm = Evm::<C>::default();
        let gas_price_oracle =
            GasPriceOracle::new(evm, gas_price_oracle_config, fee_history_cache_config);

        let rollup = "citrea";
        let arch = std::env::consts::ARCH;
        let rustc_v = version();

        let git_latest_tag = match get_latest_git_tag() {
            Ok(tag) => tag,
            Err(e) => {
                info!("Failed to get latest git tag: {}", e);
                "unknown".to_string()
            }
        };

        let current_version = format!("{}/{}/{}/rust-{}", rollup, git_latest_tag, arch, rustc_v);

        Self {
            da_service,
            batch_builder,
            gas_price_oracle,
            #[cfg(feature = "local")]
            eth_signer,
            storage,
            sequencer_client,
            web3_client_version: current_version,
        }
    }
}

impl<C: sov_modules_api::Context, Da: DaService> Ethereum<C, Da> {
    fn make_raw_tx(
        &self,
        raw_tx: RlpEvmTransaction,
    ) -> Result<(H256, Vec<u8>), jsonrpsee::core::Error> {
        let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

        let tx_hash = signed_transaction.hash();

        let tx = CallMessage { txs: vec![raw_tx] };
        let message = <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(tx);

        Ok((H256::from(tx_hash), message))
    }

    fn add_messages(&self, messages: Vec<Vec<u8>>) {
        self.batch_builder.lock().unwrap().add_messages(messages);
    }
}

fn register_rpc_methods<C: sov_modules_api::Context, Da: DaService>(
    rpc: &mut RpcModule<Ethereum<C, Da>>,
    // Checks wether the running node is a sequencer or not, if it is not a sequencer it should also have methods like eth_sendRawTransaction here.
    is_sequencer: bool,
) -> Result<(), jsonrpsee::core::Error> {
    rpc.register_async_method("web3_clientVersion", |_, ethereum| async move {
        info!("eth module: web3_clientVersion");

        Ok::<_, ErrorObjectOwned>(ethereum.web3_client_version.clone())
    })?;

    rpc.register_async_method("web3_sha3", |params, _| async move {
        info!("eth module: web3_sha3");
        let data: Bytes = params.one()?;

        let hash = H256::from_slice(keccak256(&data).as_slice());

        Ok::<_, ErrorObjectOwned>(hash)
    })?;

    rpc.register_async_method("eth_gasPrice", |_, ethereum| async move {
        info!("eth module: eth_gasPrice");
        let price = {
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());

            let suggested_tip = ethereum
                .gas_price_oracle
                .suggest_tip_cap(&mut working_set)
                .await
                .unwrap();

            let evm = Evm::<C>::default();
            let base_fee = evm
                .get_block_by_number(None, None, &mut working_set)
                .unwrap()
                .unwrap()
                .header
                .base_fee_per_gas
                .unwrap_or_default();

            suggested_tip + base_fee
        };

        Ok::<U256, ErrorObjectOwned>(price)
    })?;

    rpc.register_async_method("eth_maxFeePerGas", |_, ethereum| async move {
        let max_fee_per_gas = {
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());

            ethereum
                .gas_price_oracle
                .suggest_tip_cap(&mut working_set)
                .await
                .unwrap()
        };

        Ok::<U256, ErrorObjectOwned>(max_fee_per_gas)
    })?;

    rpc.register_async_method("eth_feeHistory", |params, ethereum| async move {
        info!("eth module: eth_feeHistory");
        let (block_count, newest_block, reward_percentiles): (
            String,
            BlockNumberOrTag,
            Option<Vec<f64>>,
        ) = params.parse()?;

        // convert block count to u64 from hex
        let block_count = u64::from_str_radix(&block_count[2..], 16)
            .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

        let fee_history = {
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());

            ethereum
                .gas_price_oracle
                .fee_history(
                    block_count,
                    newest_block,
                    reward_percentiles,
                    &mut working_set,
                )
                .await
                .unwrap()
        };

        Ok::<FeeHistory, ErrorObjectOwned>(fee_history)
    })?;

    // rpc.register_async_method("eth_publishBatch", |params, ethereum| async move {
    //     info!("eth module: eth_publishBatch");

    //     let mut params_iter = params.sequence();

    //     let mut txs = Vec::default();
    //     while let Some(tx) = params_iter.optional_next::<Vec<u8>>()? {
    //         txs.push(tx)
    //     }

    //     ethereum
    //         .build_and_submit_batch(txs, Some(1))
    //         .await
    //         .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

    //     Ok::<String, ErrorObjectOwned>("Submitted transaction".to_string())
    // })?;

    // rpc.register_async_method(
    //     "eth_sendRawTransaction",
    //     |parameters, ethereum| async move {
    //         info!("eth module: eth_sendRawTransaction");

    //         let data: Bytes = parameters.one().unwrap();

    //         let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };

    //         let (tx_hash, raw_message) = ethereum
    //             .make_raw_tx(raw_evm_tx)
    //             .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

    //         ethereum.add_messages(vec![raw_message]);

    //         Ok::<_, ErrorObjectOwned>(tx_hash)
    //     },
    // )?;

    #[cfg(feature = "local")]
    rpc.register_async_method("eth_accounts", |_, ethereum| async move {
        info!("eth module: eth_accounts");

        Ok::<_, ErrorObjectOwned>(ethereum.eth_signer.signers())
    })?;

    #[cfg(feature = "local")]
    rpc.register_async_method("eth_sendTransaction", |parameters, ethereum| async move {
        info!("eth module: eth_sendTransaction");

        let mut transaction_request: TransactionRequest = parameters.one().unwrap();

        let evm = Evm::<C>::default();

        // get from, return error if none
        let from = transaction_request
            .from
            .ok_or(to_jsonrpsee_error_object("No from address", ETH_RPC_ERROR))?;

        // return error if not in signers
        if !ethereum.eth_signer.signers().contains(&from) {
            return Err(to_jsonrpsee_error_object(
                "From address not in signers",
                ETH_RPC_ERROR,
            ));
        }

        let raw_evm_tx = {
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());

            // set nonce if none
            if transaction_request.nonce.is_none() {
                let nonce = evm
                    .get_transaction_count(from, None, &mut working_set)
                    .unwrap_or_default();

                transaction_request.nonce = Some(nonce);
            }

            // get current chain id
            let chain_id = evm
                .chain_id(&mut working_set)
                .expect("Failed to get chain id")
                .map(|id| id.as_u64())
                .unwrap_or(1);

            // get call request to estimate gas and gas prices
            let (call_request, gas_price, max_fee_per_gas) =
                get_call_request_and_params(from, chain_id, &transaction_request);

            // estimate gas limit
            let gas_limit = U256::from(
                evm.eth_estimate_gas(call_request, None, &mut working_set)?
                    .as_u64(),
            );

            // get typed transaction request
            let transaction_request = match transaction_request.into_typed_request() {
                Some(TypedTransactionRequest::Legacy(mut m)) => {
                    m.chain_id = Some(chain_id);
                    m.gas_limit = gas_limit;
                    m.gas_price = gas_price;

                    TypedTransactionRequest::Legacy(m)
                }
                Some(TypedTransactionRequest::EIP2930(mut m)) => {
                    m.chain_id = chain_id;
                    m.gas_limit = gas_limit;
                    m.gas_price = gas_price;

                    TypedTransactionRequest::EIP2930(m)
                }
                Some(TypedTransactionRequest::EIP1559(mut m)) => {
                    m.chain_id = chain_id;
                    m.gas_limit = gas_limit;
                    m.max_fee_per_gas = max_fee_per_gas;

                    TypedTransactionRequest::EIP1559(m)
                }
                None => {
                    return Err(to_jsonrpsee_error_object(
                        "Conflicting fee fields",
                        ETH_RPC_ERROR,
                    ));
                }
            };

            // get raw transaction
            let transaction = into_transaction(transaction_request).map_err(|_| {
                to_jsonrpsee_error_object("Invalid types in transaction request", ETH_RPC_ERROR)
            })?;

            // sign transaction
            let signed_tx = ethereum
                .eth_signer
                .sign_transaction(transaction, from)
                .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

            RlpEvmTransaction {
                rlp: signed_tx.envelope_encoded().to_vec(),
            }
        };
        let (tx_hash, raw_message) = ethereum
            .make_raw_tx(raw_evm_tx)
            .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;

        ethereum.add_messages(vec![raw_message]);

        Ok::<_, ErrorObjectOwned>(tx_hash)
    })?;

    if !is_sequencer {
        rpc.register_async_method(
            "eth_sendRawTransaction",
            |parameters, ethereum| async move {
                info!("Full Node: eth_sendRawTransaction");
                // send this directly to the sequencer
                let data: Bytes = parameters.one().unwrap();
                // sequencer client should send it
                let tx_hash = ethereum
                    .sequencer_client
                    .as_ref()
                    .unwrap()
                    .send_raw_tx(data)
                    .await;

                tx_hash.map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))
            },
        )?;
    }

    Ok(())
}

// Temporary solution until https://github.com/paradigmxyz/reth/issues/4704 is resolved
// The problem is having wrong length nonce/gas_limt/value fields in the transaction request
fn into_transaction(
    request: TypedTransactionRequest,
) -> Result<reth_primitives::Transaction, TryFromSliceError> {
    Ok(match request {
        TypedTransactionRequest::Legacy(tx) => {
            reth_primitives::Transaction::Legacy(reth_primitives::TxLegacy {
                chain_id: tx.chain_id,
                nonce: tx.nonce.as_u64(),
                gas_price: u128::from_be_bytes(tx.gas_price.to_be_bytes()),
                gas_limit: convert_u256_to_u64(tx.gas_limit)?,
                to: tx.kind.into(),
                value: convert_u256_to_u128(tx.value)?,
                input: tx.input,
            })
        }
        TypedTransactionRequest::EIP2930(tx) => {
            reth_primitives::Transaction::Eip2930(reth_primitives::TxEip2930 {
                chain_id: tx.chain_id,
                nonce: tx.nonce.as_u64(),
                gas_price: u128::from_be_bytes(tx.gas_price.to_be_bytes()),
                gas_limit: convert_u256_to_u64(tx.gas_limit)?,
                to: tx.kind.into(),
                value: convert_u256_to_u128(tx.value)?,
                input: tx.input,
                access_list: tx.access_list,
            })
        }
        TypedTransactionRequest::EIP1559(tx) => {
            reth_primitives::Transaction::Eip1559(reth_primitives::TxEip1559 {
                chain_id: tx.chain_id,
                nonce: tx.nonce.as_u64(),
                max_fee_per_gas: u128::from_be_bytes(tx.max_fee_per_gas.to_be_bytes()),
                gas_limit: convert_u256_to_u64(tx.gas_limit)?,
                to: tx.kind.into(),
                value: convert_u256_to_u128(tx.value)?,
                input: tx.input,
                access_list: tx.access_list,
                max_priority_fee_per_gas: u128::from_be_bytes(
                    tx.max_priority_fee_per_gas.to_be_bytes(),
                ),
            })
        }
    })
}

fn convert_u256_to_u64(u256: reth_primitives::U256) -> Result<u64, TryFromSliceError> {
    let bytes: [u8; 32] = u256.to_be_bytes();
    let bytes: [u8; 8] = bytes[24..].try_into()?;
    Ok(u64::from_be_bytes(bytes))
}

fn convert_u256_to_u128(u256: reth_primitives::U256) -> Result<u128, TryFromSliceError> {
    let bytes: [u8; 32] = u256.to_be_bytes();
    let bytes: [u8; 16] = bytes[16..].try_into()?;
    Ok(u128::from_be_bytes(bytes))
}

fn get_call_request_and_params(
    from: reth_primitives::H160,
    chain_id: u64,
    transaction_request: &TransactionRequest,
) -> (CallRequest, U128, U128) {
    // TODO: we need an oracle to fetch the gas price of the current chain
    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/883
    let gas_price = transaction_request.gas_price.unwrap_or_default();
    let max_fee_per_gas = transaction_request.max_fee_per_gas.unwrap_or_default();

    // TODO: Generate call request better according to the transaction type
    // https://github.com/Sovereign-Labs/sovereign-sdk/issues/946
    let call_request = CallRequest {
        from: Some(from),
        to: transaction_request.to,
        gas: transaction_request.gas,
        gas_price: {
            if transaction_request.max_priority_fee_per_gas.is_some() {
                // eip 1559
                None
            } else {
                // legacy
                Some(U256::from(gas_price))
            }
        },
        max_fee_per_gas: Some(U256::from(max_fee_per_gas)),
        value: transaction_request.value,
        input: transaction_request.data.clone().into(),
        nonce: transaction_request.nonce,
        chain_id: Some(chain_id.into()),
        access_list: transaction_request.access_list.clone(),
        max_priority_fee_per_gas: {
            if transaction_request.max_priority_fee_per_gas.is_some() {
                // eip 1559
                Some(U256::from(
                    transaction_request
                        .max_priority_fee_per_gas
                        .unwrap_or(max_fee_per_gas),
                ))
            } else {
                // legacy
                None
            }
        },
        transaction_type: None,
        blob_versioned_hashes: vec![],
        max_fee_per_blob_gas: None,
    };

    (call_request, gas_price, max_fee_per_gas)
}

pub fn get_latest_git_tag() -> Result<String, ErrorObjectOwned> {
    let latest_tag_commit = Command::new("git")
        .args(["rev-list", "--tags", "--max-count=1"])
        .output()
        .map_err(|e| to_jsonrpsee_error_object(e, "Failed to get version"))?;

    if !latest_tag_commit.status.success() {
        return Err(to_jsonrpsee_error_object(
            "Failure",
            "Failed to get version",
        ));
    }

    let latest_tag_commit = String::from_utf8_lossy(&latest_tag_commit.stdout)
        .trim()
        .to_string();

    let latest_tag = Command::new("git")
        .args(["describe", "--tags", &latest_tag_commit])
        .output()
        .map_err(|e| to_jsonrpsee_error_object(e, "Failed to get version"))?;

    if !latest_tag.status.success() {
        return Err(to_jsonrpsee_error_object(
            "Failure",
            "Failed to get version",
        ));
    }

    Ok(String::from_utf8_lossy(&latest_tag.stdout)
        .trim()
        .to_string())
}
