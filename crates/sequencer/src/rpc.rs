use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use alloy_eips::eip2718::Encodable2718;
use alloy_eips::BlockId;
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types::Transaction;
use citrea_common::rpc::utils::internal_rpc_error;
use citrea_evm::Evm;
use citrea_stf::runtime::DefaultContext;
use jsonrpsee::core::{RpcResult, SubscriptionResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorCode, ErrorObject};
use jsonrpsee::{PendingSubscriptionSink, SubscriptionSink};
use parking_lot::Mutex;
use reth_rpc::eth::EthTxBuilder;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_types_compat::TransactionCompat;
use reth_transaction_pool::{EthPooledTransaction, PoolTransaction};
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps};
use sov_modules_api::{Spec, WorkingSet};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::rpc::{L2BlockIdentifier, LedgerRpcProvider, MempoolTransactionSignal};
use tokio::sync::broadcast;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error};

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::metrics::SEQUENCER_METRICS;
use crate::types::SequencerRpcMessage;
use crate::utils::recover_raw_transaction;

/// Result of receiving blocks from the `l2_block_rx` channel
enum BlockReceiveResult {
    /// Successfully received blocks (may include recovered lagged blocks)
    HighestBlock(u64),
    /// Channel was closed
    ChannelClosed,
}

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
    /// Broadcast receiver for L2 block notifications
    pub l2_block_rx: broadcast::Receiver<u64>,
    /// Broadcast sender for mempool transactions accepted in `eth_sendRawTransaction`
    pub mempool_transaction_tx: broadcast::Sender<MempoolTransactionSignal>,
    /// Broadcast receiver for mempool transaction notifications
    pub mempool_transaction_rx: broadcast::Receiver<MempoolTransactionSignal>,
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
/// * `l2_block_rx` - Broadcast receiver for L2 block notifications
#[allow(clippy::too_many_arguments)]
pub fn create_rpc_context(
    mempool: Arc<CitreaMempool>,
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    rpc_message_tx: UnboundedSender<SequencerRpcMessage>,
    storage: <DefaultContext as Spec>::Storage,
    ledger_db: LedgerDB,
    test_mode: bool,
    l2_block_rx: broadcast::Receiver<u64>,
    mempool_transaction_tx: broadcast::Sender<MempoolTransactionSignal>,
    mempool_transaction_rx: broadcast::Receiver<MempoolTransactionSignal>,
) -> RpcContext {
    RpcContext {
        mempool,
        deposit_mempool,
        rpc_message_tx,
        storage,
        ledger: ledger_db,
        test_mode,
        l2_block_rx,
        mempool_transaction_tx,
        mempool_transaction_rx,
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

    /// Subscribe to Citrea events
    #[subscription(name = "citrea_subscribe" => "citrea_subscription", unsubscribe = "citrea_unsubscribe", item = L2BlockResponse)]
    async fn subscribe_citrea(&self, topic: String) -> SubscriptionResult;
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

        if let Err(e) =
            self.context
                .mempool_transaction_tx
                .send(MempoolTransactionSignal::NewTransaction((
                    hash,
                    rlp_encoded_tx.clone(),
                )))
        {
            tracing::warn!("Failed to send new transaction signal: {:?}", e);
        }

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
            Some(BlockId::pending()),
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

    /// Subscribe to Citrea events
    async fn subscribe_citrea(
        &self,
        pending: PendingSubscriptionSink,
        topic: String,
    ) -> SubscriptionResult {
        match topic.as_str() {
            "newL2Blocks" => {
                let subscription = pending.accept().await?;
                let mut rx = self.context.l2_block_rx.resubscribe();
                let ledger = self.context.ledger.clone();

                tokio::spawn(async move {
                    handle_l2_block_subscription(subscription, &mut rx, ledger).await;
                });
            }
            "mempoolTransactions" => {
                let subscription = pending.accept().await?;
                let mut rx = self.context.mempool_transaction_rx.resubscribe();
                tokio::spawn(async move {
                    loop {
                        if let Ok(response) = rx.recv().await {
                            if let Err(e) = subscription
                                .send_timeout(
                                    jsonrpsee::SubscriptionMessage::new(
                                        subscription.method_name(),
                                        subscription.subscription_id(),
                                        &response,
                                    )
                                    .unwrap(),
                                    std::time::Duration::from_secs(10),
                                )
                                .await
                            {
                                tracing::debug!("Failed to send mempool transaction: {}", e);
                                return false; // End subscription
                            }
                        }
                    }
                });
            }
            _ => {
                pending
                    .reject(internal_rpc_error("Unsupported subscription topic"))
                    .await;
            }
        }
        Ok(())
    }
}

/// Get L2 block response by block height
async fn get_l2_block_response(
    block_height: u64,
    ledger: &LedgerDB,
) -> Result<L2BlockResponse, Box<dyn std::error::Error + Send + Sync>> {
    let l2_block = ledger
        .get_l2_block(&L2BlockIdentifier::Number(block_height))?
        .ok_or(format!("L2 block at height {} not found", block_height))?;

    Ok(l2_block)
}

/// Handle L2 block subscription, including lagged block recovery
async fn handle_l2_block_subscription(
    subscription: SubscriptionSink,
    rx: &mut tokio::sync::broadcast::Receiver<u64>,
    ledger: LedgerDB,
) {
    let head_block_num = ledger.get_head_l2_block_height().unwrap_or(0);
    let last_sent_block = AtomicU64::new(head_block_num);
    loop {
        match receive_next_blocks(rx, &last_sent_block).await {
            BlockReceiveResult::HighestBlock(highest_block_height) => {
                let last_sent_block_num = last_sent_block.load(Ordering::SeqCst);
                for block_height in last_sent_block_num + 1..=highest_block_height {
                    if !send_block_notification(&subscription, block_height, &ledger).await {
                        return;
                    }
                }
                last_sent_block.store(highest_block_height, Ordering::SeqCst);
            }
            BlockReceiveResult::ChannelClosed => {
                tracing::info!("L2 block channel closed, ending subscription");
                return;
            }
        }
    }
}

/// Receive the next block(s) from the channel, handling lag recovery
async fn receive_next_blocks(
    rx: &mut broadcast::Receiver<u64>,
    last_sent_block: &AtomicU64,
) -> BlockReceiveResult {
    match rx.recv().await {
        Ok(block_height) => BlockReceiveResult::HighestBlock(block_height),
        Err(broadcast::error::RecvError::Lagged(num_lagged)) => {
            tracing::warn!(
                "Subscription lagged by {} blocks, attempting to recover",
                num_lagged
            );

            // Explanation of lag recovery:
            // If the channel size is for example 10 and we somehow sent 30 blocks at the same time to the channel,
            // The first 20 blocks will be dropped and we will only receive the last 10 blocks.
            // Since we send blocks sequentially, we can recover the lagged blocks by
            // calculating the range of blocks that were missed based on the last sent block number.
            // Assume our last sent block number is 0, initial state, we receive a lagged error with num_lagged = 20.
            // We return blocks from 1 to 20 to recover from the lag. After that when we call receive again,
            // we will receive the next block, which is 21, and continue from there as normal.

            // Recover blocks from the `last_sent_block + 1`, to `last_sent_block + num_lagged`
            let last_sent_block_num = last_sent_block.load(Ordering::SeqCst);
            BlockReceiveResult::HighestBlock(last_sent_block_num + num_lagged)
        }
        Err(broadcast::error::RecvError::Closed) => BlockReceiveResult::ChannelClosed,
    }
}

/// Send a block notification to the subscriber
async fn send_block_notification(
    subscription: &SubscriptionSink,
    block_height: u64,
    ledger: &LedgerDB,
) -> bool {
    let block_response = match get_l2_block_response(block_height, ledger).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Failed to get L2 block {} response: {}", block_height, e);
            return true; // Continue subscription despite this error
        }
    };

    if let Err(e) = subscription
        .send_timeout(
            jsonrpsee::SubscriptionMessage::new(
                subscription.method_name(),
                subscription.subscription_id(),
                &block_response,
            )
            .unwrap(),
            std::time::Duration::from_secs(10),
        )
        .await
    {
        tracing::debug!("Failed to send L2 block notification: {}", e);
        return false; // End subscription
    }

    true
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
