use std::sync::Arc;

use alloy_primitives::{Bytes, B256};
use alloy_rlp::Encodable;
use alloy_rpc_types::Transaction;
use citrea_evm::Evm;
use futures::channel::mpsc::UnboundedSender;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::{ErrorCode, ErrorObject, ErrorObjectOwned};
use parking_lot::Mutex;
use reth_rpc::eth::helpers::types::EthTxBuilder;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_types_compat::transaction::from_recovered;
use reth_rpc_types_compat::TransactionCompat;
use reth_transaction_pool::{EthPooledTransaction, PoolTransaction};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_api::WorkingSet;
use tracing::{debug, error};

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::utils::recover_raw_transaction;

pub(crate) struct RpcContext<C: sov_modules_api::Context, DB: SequencerLedgerOps> {
    pub mempool: Arc<CitreaMempool<C>>,
    pub deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    pub l2_force_block_tx: UnboundedSender<()>,
    pub storage: C::Storage,
    pub ledger: DB,
    pub test_mode: bool,
}

#[rpc(client, server)]
pub trait SequencerRpc {
    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256>;

    #[method(name = "eth_getTransactionByHash")]
    #[blocking]
    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>>;

    #[method(name = "citrea_sendRawDepositTransaction")]
    #[blocking]
    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()>;

    #[method(name = "citrea_testPublishBlock")]
    async fn publish_test_block(&self) -> RpcResult<()>;
}

pub struct SequencerRpcServerImpl<
    C: sov_modules_api::Context,
    DB: SequencerLedgerOps + Send + Sync + 'static,
> {
    context: Arc<RpcContext<C, DB>>,
}

impl<C: sov_modules_api::Context, DB: SequencerLedgerOps + Send + Sync + 'static>
    SequencerRpcServerImpl<C, DB>
{
    pub fn new(context: RpcContext<C, DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<C: sov_modules_api::Context, DB: SequencerLedgerOps + Send + Sync + 'static> SequencerRpcServer
    for SequencerRpcServerImpl<C, DB>
{
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256> {
        debug!("Sequencer: eth_sendRawTransaction");

        let recovered = recover_raw_transaction(data.clone())?;
        let pool_transaction = EthPooledTransaction::from_pooled(recovered);

        let hash = self
            .context
            .mempool
            .add_external_transaction(pool_transaction.clone())
            .await
            .map_err(EthApiError::from)?;

        let mut rlp_encoded_tx = Vec::new();
        pool_transaction
            .transaction()
            .clone()
            .into_signed()
            .encode(&mut rlp_encoded_tx);

        // Do not return error here just log
        if let Err(e) = self
            .context
            .ledger
            .insert_mempool_tx(hash.to_vec(), rlp_encoded_tx)
        {
            tracing::warn!("Failed to insert mempool tx into db: {:?}", e);
        }

        Ok(hash)
    }

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
                let tx_signed_ec_recovered = tx.to_recovered_transaction(); // tx signed ec recovered
                let tx: Transaction = from_recovered::<EthTxBuilder>(tx_signed_ec_recovered).inner;
                Ok::<Option<Transaction>, ErrorObjectOwned>(Some(tx))
            }
            None => match mempool_only {
                Some(true) => Ok::<Option<Transaction>, ErrorObjectOwned>(None),
                _ => {
                    let evm = Evm::<C>::default();
                    let mut working_set = WorkingSet::<C>::new(self.context.storage.clone());

                    match evm.get_transaction_by_hash(hash, &mut working_set) {
                        Ok(tx) => Ok::<Option<Transaction>, ErrorObjectOwned>(
                            tx.map(|transaction| transaction.inner),
                        ),
                        Err(e) => Err(e),
                    }
                }
            },
        }
    }

    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()> {
        debug!("Sequencer: citrea_sendRawDepositTransaction");

        let evm = Evm::<C>::default();
        let mut working_set = WorkingSet::<C>::new(self.context.storage.clone());

        let dep_tx = self
            .context
            .deposit_mempool
            .lock()
            .make_deposit_tx_from_data(deposit.clone().into());

        let tx_res = evm.get_call(dep_tx, None, None, None, &mut working_set);

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

    async fn publish_test_block(&self) -> RpcResult<()> {
        if !self.context.test_mode {
            return Err(ErrorObject::from(ErrorCode::MethodNotFound).to_owned());
        }

        debug!("Sequencer: citrea_testPublishBlock");
        self.context
            .l2_force_block_tx
            .unbounded_send(())
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Could not send L2 force block transaction: {e}")),
                )
            })
    }
}

pub fn create_rpc_module<
    C: sov_modules_api::Context,
    DB: SequencerLedgerOps + Send + Sync + 'static,
>(
    rpc_context: RpcContext<C, DB>,
) -> jsonrpsee::RpcModule<SequencerRpcServerImpl<C, DB>> {
    let server = SequencerRpcServerImpl::new(rpc_context);

    SequencerRpcServer::into_rpc(server)
}
