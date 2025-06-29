use std::sync::Arc;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types::Transaction;
use citrea_common::rpc::utils::internal_rpc_error;
use citrea_evm::Evm;
use citrea_stf::runtime::DefaultContext;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorCode, ErrorObject};
use parking_lot::Mutex;
use reth_rpc::eth::EthTxBuilder;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_types_compat::TransactionCompat;
use reth_transaction_pool::{EthPooledTransaction, PoolTransaction};
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps};
use sov_modules_api::{Spec, WorkingSet};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error};

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::metrics::SEQUENCER_METRICS;
use crate::types::SequencerRpcMessage;
use crate::utils::recover_raw_transaction;

/// RPC context containing all the shared data needed for RPC method implementations
pub struct RpcContext {
    /// The transaction mempool
    pub mempool: Arc<CitreaMempool>,
    /// The deposit transaction mempool
    pub deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    /// Channel for sending messages to the sequencer
    pub rpc_message_tx: UnboundedSender<SequencerRpcMessage>,
    /// Storage for the sequencer state
    pub storage: <DefaultContext as Spec>::Storage,
    /// Ledger database access
    pub ledger: LedgerDB,
    /// Whether the sequencer is running in test mode
    pub test_mode: bool,
}

/// Creates a shared RpcContext with all required data.
///
/// # Arguments
/// * `mempool` - The transaction mempool
/// * `deposit_mempool` - The deposit transaction mempool
/// * `l2_force_block_tx` - Channel for forcing block production
/// * `storage` - Storage for the sequencer state
/// * `ledger_db` - Ledger database access
/// * `test_mode` - Whether the sequencer is running in test mode
pub fn create_rpc_context(
    mempool: Arc<CitreaMempool>,
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    rpc_message_tx: UnboundedSender<SequencerRpcMessage>,
    storage: <DefaultContext as Spec>::Storage,
    ledger_db: LedgerDB,
    test_mode: bool,
) -> RpcContext {
    RpcContext {
        mempool,
        deposit_mempool,
        rpc_message_tx,
        storage,
        ledger: ledger_db,
        test_mode,
    }
}

/// Updates the given RpcModule with Sequencer methods.
///
/// # Arguments
/// * `rpc_context` - The context containing all required data for RPC methods
/// * `rpc_methods` - The RPC module to extend with sequencer methods
///
/// # Returns
/// The updated RPC module or a registration error
pub fn register_rpc_methods(
    rpc_context: RpcContext,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

/// Interface definition for the sequencer RPC calls.
///
/// This trait defines all available RPC methods that can be called on the sequencer.
#[rpc(client, server)]
pub trait SequencerRpc {
    /// Submits a raw transaction to the mempool
    ///
    /// # Arguments
    /// * `data` - The raw transaction data
    ///
    /// # Returns
    /// The transaction hash
    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256>;

    /// Retrieves transaction information by hash
    ///
    /// This implements the standard Ethereum JSON-RPC `eth_getTransactionByHash` method with
    /// an additional feature to query only mempool transactions.
    ///
    /// The method first checks the mempool for the transaction. If not found, it will check
    /// the blockchain state unless `mempool_only` is set to true.
    ///
    /// # Arguments
    /// * `hash` - The transaction hash
    /// * `mempool_only` - If true, only check the mempool. Default is false.
    ///    This is a Citrea-specific extension to the standard Ethereum RPC.
    ///
    /// # Returns
    /// * If the transaction is in the mempool: Returns the pending transaction details
    /// * If mempool_only is false and not in mempool: Searches the blockchain state
    /// * If not found in either location: Returns None
    ///
    /// This extended functionality allows clients to specifically query for
    /// transactions that haven't been included in a block yet.
    #[method(name = "eth_getTransactionByHash")]
    #[blocking]
    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>>;

    /// Submits a raw deposit transaction
    ///
    /// # Arguments
    /// * `deposit` - The raw deposit transaction data
    ///
    /// # Processing Steps
    /// 1. Creates a deposit transaction from the raw data
    /// 2. Performs an eth_call simulation with the deposit data against the bridge contract
    ///    to validate that the deposit would succeed
    /// 3. If the simulation succeeds, adds the deposit to the FIFO deposit mempool
    /// 4. If the simulation fails, returns an error
    ///
    /// This ensures deposits are valid before being accepted into the mempool.
    #[method(name = "citrea_sendRawDepositTransaction")]
    #[blocking]
    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()>;

    /// Forces block production in test mode
    ///
    /// This method is only available when the sequencer is running in test mode.
    #[method(name = "citrea_testPublishBlock")]
    async fn publish_test_block(&self) -> RpcResult<()>;

    /// Halt sequencer commitments
    #[method(name = "citrea_haltCommitments")]
    async fn halt_commitments(&self) -> RpcResult<()>;

    /// Resume sequencer commitments
    #[method(name = "citrea_resumeCommitments")]
    async fn resume_commitments(&self) -> RpcResult<()>;
}

/// Sequencer RPC server implementation
///
/// Handles all RPC method calls by delegating to the appropriate services
pub struct SequencerRpcServerImpl {
    /// The shared RPC context containing all required data
    context: Arc<RpcContext>,
}

impl SequencerRpcServerImpl {
    /// Creates a new instance of the sequencer RPC server.
    ///
    /// # Arguments
    /// * `context` - The shared RPC context containing all required data
    pub fn new(context: RpcContext) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl SequencerRpcServer for SequencerRpcServerImpl {
    /// eth_sendRawTransaction RPC call implementation
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256> {
        debug!("Sequencer: eth_sendRawTransaction");

        let recovered = recover_raw_transaction(data.clone())?;
        let pool_transaction = EthPooledTransaction::from_pooled(recovered);

        let rlp_encoded_tx = pool_transaction.transaction().inner().encoded_2718();

        let hash = self
            .context
            .mempool
            .add_external_transaction(pool_transaction)
            .await
            .map_err(EthApiError::from)?;

        // Do not return error here just log
        if let Err(e) = self
            .context
            .ledger
            .insert_mempool_tx(hash.to_vec(), rlp_encoded_tx)
        {
            tracing::warn!("Failed to insert mempool tx into db: {:?}", e);
        } else {
            SEQUENCER_METRICS.mempool_txs.increment(1);
            SEQUENCER_METRICS.mempool_txs_inc.increment(1);
        }

        Ok(hash)
    }

    /// Implementation of the standard Ethereum eth_getTransactionByHash RPC method
    /// with Citrea's mempool-only extension.
    ///
    /// The implementation follows this flow:
    /// 1. First checks the mempool for the transaction
    /// 2. If found in mempool:
    ///    - Converts it to a transaction
    ///    - Returns it as a pending transaction
    /// 3. If not in mempool and mempool_only is true:
    ///    - Returns None immediately
    /// 4. If not in mempool and mempool_only is false:
    ///    - Searches the blockchain state using the EVM
    ///    - Returns the transaction if found, None if not
    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>> {
        debug!(
            "Sequencer: eth_getTransactionByHash({}, {:?})",
            hash, mempool_only
        );

        match self.context.mempool.get(&hash) {
            Some(tx) => {
                let tx_signed_ec_recovered = tx.to_consensus(); // tx signed ec recovered
                let tx = EthTxBuilder::default()
                    .fill_pending(tx_signed_ec_recovered)
                    .expect("EthTxBuilder fill can't fail");
                Ok(Some(tx))
            }
            None => match mempool_only {
                Some(true) => Ok(None),
                _ => {
                    let evm = Evm::<DefaultContext>::default();
                    let mut working_set = WorkingSet::new(self.context.storage.clone());

                    match evm.get_transaction_by_hash(hash, &mut working_set) {
                        Ok(tx) => Ok(tx),
                        Err(e) => Err(e),
                    }
                }
            },
        }
    }

    /// eth_sendRawDepositTransaction RPC call implementation
    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()> {
        debug!("Sequencer: citrea_sendRawDepositTransaction");

        let evm = Evm::<DefaultContext>::default();
        let mut working_set = WorkingSet::new(self.context.storage.clone());

        let dep_tx = self
            .context
            .deposit_mempool
            .lock()
            .make_deposit_tx_from_data(deposit.clone().into());

        let tx_res = evm.get_call(
            dep_tx,
            None,
            None,
            None,
            &mut working_set,
            &self.context.ledger,
        );

        match tx_res {
            Ok(hex_res) => {
                tracing::debug!("Deposit tx processed successfully {}", hex_res);
                self.context
                    .deposit_mempool
                    .lock()
                    .add_deposit_tx(deposit.to_vec());
                Ok(())
            }
            Err(e) => {
                error!("Error processing deposit tx: {:?}", e);
                Err(e)
            }
        }
    }

    /// Sends a sequencer test block signal
    ///
    /// This is mostly used for testing purposes with a mock DA layer.
    async fn publish_test_block(&self) -> RpcResult<()> {
        if !self.context.test_mode {
            return Err(ErrorObject::from(ErrorCode::MethodNotFound).to_owned());
        }

        debug!("Sequencer: citrea_testPublishBlock");
        self.context
            .rpc_message_tx
            .send(SequencerRpcMessage::ProduceTestBlock)
            .map_err(|e| {
                internal_rpc_error(format!("Could not send L2 force block transaction: {e}"))
            })
    }

    /// Halt sequencer commitments
    async fn halt_commitments(&self) -> RpcResult<()> {
        debug!("Sequencer: citrea_haltCommitments");
        self.context
            .rpc_message_tx
            .send(SequencerRpcMessage::HaltCommitments)
            .map_err(|e| internal_rpc_error(format!("Could not send halt commitments signal: {e}")))
    }

    /// Resume sequencer commitments
    async fn resume_commitments(&self) -> RpcResult<()> {
        debug!("Sequencer: citrea_resumeCommitments");
        self.context
            .rpc_message_tx
            .send(SequencerRpcMessage::ResumeCommitments)
            .map_err(|e| {
                internal_rpc_error(format!("Could not send resume commitments signal: {e}"))
            })
    }
}

/// Creates and returns the sequencer RPC module with all methods registered
///
/// # Arguments
/// * `rpc_context` - The shared RPC context containing all required data
///
/// # Returns
/// The configured RPC module
pub fn create_rpc_module(rpc_context: RpcContext) -> jsonrpsee::RpcModule<SequencerRpcServerImpl> {
    let server = SequencerRpcServerImpl::new(rpc_context);

    SequencerRpcServer::into_rpc(server)
}
