use std::sync::Arc;

use citrea_evm::Evm;
use futures::channel::mpsc::UnboundedSender;
use jsonrpsee::core::Error as RpcError;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::{Bytes, FromRecoveredPooledTransaction, IntoRecoveredTransaction, B256};
use reth_rpc::eth::error::EthApiError;
use reth_rpc_types_compat::transaction::from_recovered;
use reth_transaction_pool::EthPooledTransaction;
use shared_backup_db::PostgresConnector;
use sov_mock_da::{MockAddress, MockDaService};
use sov_modules_api::WorkingSet;
use tokio::sync::Mutex;
use tracing::info;

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::utils::recover_raw_transaction;

pub(crate) struct RpcContext<C: sov_modules_api::Context> {
    pub mempool: Arc<CitreaMempool<C>>,
    pub deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    pub l2_force_block_tx: UnboundedSender<()>,
    pub storage: C::Storage,
    pub test_mode: bool,
    pub pg_pool: Option<Arc<PostgresConnector>>,
}

pub(crate) fn create_rpc_module<C: sov_modules_api::Context>(
    rpc_context: RpcContext<C>,
) -> Result<RpcModule<RpcContext<C>>, RpcError> {
    let test_mode = rpc_context.test_mode;
    let mut rpc = RpcModule::new(rpc_context);
    rpc.register_async_method("eth_sendRawTransaction", |parameters, ctx| async move {
        info!("Sequencer: eth_sendRawTransaction");
        let data: Bytes = parameters.one()?;

        // Only check if the signature is valid for now
        let recovered: reth_primitives::PooledTransactionsElementEcRecovered =
            recover_raw_transaction(data.clone())?;

        let pool_transaction = EthPooledTransaction::from_recovered_pooled_transaction(recovered);

        // submit the transaction to the pool with an `External` origin
        let hash: B256 = ctx
            .mempool
            .add_external_transaction(pool_transaction.clone())
            .await
            .map_err(EthApiError::from)?;

        if let Some(pool) = &ctx.pg_pool {
            let mut rlp_encoded_tx = Vec::new();
            pool_transaction
                .to_recovered_transaction()
                .into_signed()
                .encode_enveloped(&mut rlp_encoded_tx);
            // Do not return error here just log
            match pool.insert_mempool_tx(hash.to_vec(), rlp_encoded_tx).await {
                Ok(_) => (),
                Err(e) => tracing::warn!("Failed to insert mempool tx into db: {:?}", e),
            };
        }

        Ok::<B256, ErrorObjectOwned>(hash)
    })?;

    if test_mode {
        rpc.register_async_method("citrea_testPublishBlock", |_, ctx| async move {
            info!("Sequencer: citrea_testPublishBlock");
            ctx.l2_force_block_tx.unbounded_send(()).map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Could not send L2 force block transaction: {e}")),
                )
            })?;
            Ok::<(), ErrorObjectOwned>(())
        })?;

        rpc.register_async_method("da_publishBlock", |_, _ctx| async move {
            info!("Sequencer: da_publishBlock");
            let da = MockDaService::new(MockAddress::from([0; 32]));
            da.publish_test_block().await.map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("Could not publish mock-da block: {e}")),
                )
            })?;
            Ok::<(), ErrorObjectOwned>(())
        })?;
    }

    rpc.register_async_method("eth_getTransactionByHash", |parameters, ctx| async move {
        let mut params = parameters.sequence();
        let hash: B256 = params.next()?;
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
                        Err(e) => Err(e),
                    }
                }
            },
        }
    })?;

    rpc.register_async_method(
        "citrea_sendRawDepositTransaction",
        |parameters, ctx| async move {
            let mut params = parameters.sequence();
            let deposit: Bytes = params.next()?;

            info!("Sequencer: citrea_sendRawDepositTransaction");

            let evm = Evm::<C>::default();
            let mut working_set = WorkingSet::<C>::new(ctx.storage.clone());

            let dep_tx = ctx
                .deposit_mempool
                .lock()
                .await
                .make_deposit_tx_from_data(deposit.clone().into());

            let tx_res = evm.get_call(dep_tx, None, None, None, &mut working_set);

            match tx_res {
                Ok(hex_res) => {
                    tracing::info!("Deposit tx processed successfully {}", hex_res);
                    ctx.deposit_mempool
                        .lock()
                        .await
                        .add_deposit_tx(deposit.to_vec());
                }
                Err(e) => {
                    tracing::error!("Error processing deposit tx: {:?}", e);
                    return Err(e);
                }
            }

            Ok(())
        },
    )?;
    Ok(rpc)
}
