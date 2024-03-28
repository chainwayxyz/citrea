use std::sync::Arc;

use citrea_evm::SYSTEM_SIGNER;
use reth_primitives::{BaseFeeParamsKind, Chain, ChainSpec, TxHash};
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::error::PoolError;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, PoolResult, TransactionPool, TransactionValidationTaskExecutor,
    ValidPoolTransaction,
};

pub use crate::db_provider::DbProvider;

type CitreaMempoolImpl<C> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider<C>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

type Transaction<C> = <CitreaMempoolImpl<C> as TransactionPool>::Transaction;

pub(crate) struct CitreaMempool<C: sov_modules_api::Context>(CitreaMempoolImpl<C>);

impl<C: sov_modules_api::Context> CitreaMempool<C> {
    pub(crate) fn new(client: DbProvider<C>) -> Self {
        let blob_store = NoopBlobStore::default();
        let genesis_hash = client.genesis_block().unwrap().unwrap().header.hash;
        let evm_config = client.cfg();
        let chain_spec = ChainSpec {
            chain: Chain::from_id(evm_config.chain_id),
            genesis_hash,
            base_fee_params: BaseFeeParamsKind::Constant(evm_config.base_fee_params),
            ..Default::default()
        };
        Self(Pool::eth_pool(
            TransactionValidationTaskExecutor::eth(
                client,
                Arc::new(chain_spec),
                blob_store,
                TokioTaskExecutor::default(),
            ),
            blob_store,
            Default::default(),
        ))
    }

    pub(crate) async fn add_external_transaction(
        &self,
        transaction: EthPooledTransaction,
    ) -> PoolResult<TxHash> {
        if transaction.transaction().signer() == SYSTEM_SIGNER {
            return Err(PoolError::other(
                transaction.transaction().hash(),
                "system transactions from rpc are not allowed",
            ));
        }
        self.0.add_external_transaction(transaction).await
    }

    pub(crate) fn get(&self, hash: &TxHash) -> Option<Arc<ValidPoolTransaction<Transaction<C>>>> {
        self.0.get(hash)
    }

    pub(crate) fn remove_transactions(
        &self,
        tx_hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Transaction<C>>>> {
        self.0.remove_transactions(tx_hashes)
    }

    pub(crate) fn best_transactions_with_attributes(
        &self,
        best_transactions_attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Transaction<C>>>>> {
        self.0
            .best_transactions_with_attributes(best_transactions_attributes)
    }
}
