use std::sync::Arc;

use citrea_evm::SYSTEM_SIGNER;
use reth_primitives::{Chain, ChainSpecBuilder, Genesis, TxHash};
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::error::PoolError;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, PoolConfig, PoolResult, SubPoolLimit, TransactionPool,
    TransactionValidationTaskExecutor, ValidPoolTransaction, TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT,
};

use crate::config::SequencerMempoolConfig;
pub use crate::db_provider::DbProvider;

type CitreaMempoolImpl<C> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider<C>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

type Transaction<C> = <CitreaMempoolImpl<C> as TransactionPool>::Transaction;

pub(crate) struct CitreaMempool<C: sov_modules_api::Context>(CitreaMempoolImpl<C>);

impl<C: sov_modules_api::Context> CitreaMempool<C> {
    pub(crate) fn new(client: DbProvider<C>, mempool_conf: SequencerMempoolConfig) -> Self {
        let blob_store = NoopBlobStore::default();
        let genesis_block = client.genesis_block().unwrap().unwrap();
        let evm_config = client.cfg();

        let chain_spec = ChainSpecBuilder::default()
            .chain(Chain::from_id(evm_config.chain_id))
            .shanghai_activated()
            .genesis(
                Genesis::default()
                    .with_nonce(genesis_block.header.nonce.unwrap().into())
                    .with_timestamp(genesis_block.header.timestamp.saturating_to())
                    .with_extra_data(genesis_block.header.extra_data)
                    .with_gas_limit(genesis_block.header.gas_limit.saturating_to())
                    .with_difficulty(genesis_block.header.difficulty)
                    .with_mix_hash(genesis_block.header.mix_hash.unwrap())
                    .with_coinbase(genesis_block.header.miner)
                    .with_base_fee(Some(
                        genesis_block
                            .header
                            .base_fee_per_gas
                            .unwrap()
                            .saturating_to(),
                    )),
            )
            .build();

        // Default 10x'ed from standard limits
        let pool_config = Default::default();
        let pool_config = PoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: mempool_conf.pending_tx_limit as usize,
                max_size: TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT * 10 * 1024 * 1024,
            },
            basefee_limit: SubPoolLimit {
                max_txs: mempool_conf.base_fee_limit as usize,
                max_size: TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT * 10 * 1024 * 1024,
            },
            queued_limit: SubPoolLimit {
                max_txs: mempool_conf.queue_tx_limit as usize,
                max_size: TXPOOL_SUBPOOL_MAX_SIZE_MB_DEFAULT * 10 * 1024 * 1024,
            },
            blob_limit: SubPoolLimit {
                max_txs: 0,
                max_size: 0,
            },
            max_account_slots: mempool_conf.max_account_slots as usize,
            ..pool_config
        };

        Self(Pool::eth_pool(
            TransactionValidationTaskExecutor::eth(
                client,
                Arc::new(chain_spec),
                blob_store,
                TokioTaskExecutor::default(),
            ),
            blob_store,
            pool_config,
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
