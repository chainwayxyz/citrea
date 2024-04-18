use std::sync::Arc;

use citrea_evm::Evm;
use futures::channel::mpsc::UnboundedSender;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::{Bytes, FromRecoveredPooledTransaction, IntoRecoveredTransaction, B256};
use reth_rpc::eth::error::RpcPoolError;
use reth_rpc_types_compat::transaction::from_recovered;
use reth_transaction_pool::EthPooledTransaction;
use sov_mock_da::{MockAddress, MockDaService};
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::WorkingSet;
use tracing::info;

use crate::mempool::CitreaMempool;
use crate::utils::recover_raw_transaction;

pub(crate) struct RpcContext<C: sov_modules_api::Context> {
    pub mempool: Arc<CitreaMempool<C>>,
    pub l2_force_block_tx: UnboundedSender<()>,
    pub storage: C::Storage,
}

pub(crate) fn create_rpc_module<C: sov_modules_api::Context>(
    rpc_context: RpcContext<C>,
) -> Result<RpcModule<RpcContext<C>>, jsonrpsee::core::Error> {
    let mut rpc = RpcModule::new(rpc_context);
    rpc.register_async_method("eth_sendRawTransaction", |parameters, ctx| async move {
        info!("Sequencer: eth_sendRawTransaction");
        let data: Bytes = parameters.one().unwrap();

        // Only check if the signature is valid for now
        let recovered: reth_primitives::PooledTransactionsElementEcRecovered =
            recover_raw_transaction(data.clone())?;

        let pool_transaction = EthPooledTransaction::from_recovered_pooled_transaction(recovered);

        // submit the transaction to the pool with an `External` origin
        let hash: B256 = ctx
            .mempool
            .add_external_transaction(pool_transaction)
            .await
            .map_err(|e| {
                let err = RpcPoolError::from(e);
                let error_string = err.to_string();
                to_jsonrpsee_error_object(&error_string, err)
            })?;

        Ok::<B256, ErrorObjectOwned>(hash)
    })?;
    rpc.register_async_method("eth_publishBatch", |_, ctx| async move {
        info!("Sequencer: eth_publishBatch");
        ctx.l2_force_block_tx.unbounded_send(()).unwrap();
        Ok::<(), ErrorObjectOwned>(())
    })?;
    rpc.register_async_method("da_publishBlock", |_, _ctx| async move {
        info!("Sequencer: da_publishBlock");
        let da = MockDaService::new(MockAddress::from([0; 32]));
        da.publish_test_block()
            .await
            .expect("Should publish mock-da block");
        Ok::<(), ErrorObjectOwned>(())
    })?;
    rpc.register_async_method("eth_getTransactionByHash", |parameters, ctx| async move {
        let mut params = parameters.sequence();
        let hash: B256 = params.next().unwrap();
        let mempool_only: Result<Option<bool>, ErrorObjectOwned> = params.optional_next();
        info!(
            "Sequencer: eth_getTransactionByHash({}, {:?})",
            hash, mempool_only
        );

        match ctx.mempool.get(&hash) {
            Some(tx) => {
                let tx_signed_ec_recovered = tx.to_recovered_transaction(); // tx signed ec recovered
                let tx: reth_rpc_types::Transaction = from_recovered(tx_signed_ec_recovered);
                Ok::<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>(Some(tx))
            }
            None => match mempool_only {
                Ok(Some(true)) => Ok::<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>(None),
                _ => {
                    let evm = Evm::<C>::default();
                    let mut working_set = WorkingSet::<C>::new(ctx.storage.clone());

                    match evm.get_transaction_by_hash(hash, &mut working_set) {
                        Ok(tx) => Ok::<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>(tx),
                        Err(e) => Err(to_jsonrpsee_error_object(&e.to_string(), e)),
                    }
                }
            },
        }
    })?;
    Ok(rpc)
}
