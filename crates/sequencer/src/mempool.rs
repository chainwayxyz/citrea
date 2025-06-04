use std::sync::Arc;

use alloy_eips::Typed2718;
use alloy_primitives::TxHash;
use citrea_common::SequencerMempoolConfig;
use citrea_evm::SYSTEM_SIGNER;
use citrea_primitives::MIN_BASE_FEE_PER_GAS;
use reth_execution_types::ChangedAccount;
use reth_tasks::TaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::error::{PoolError, PoolErrorKind};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, PoolConfig, PoolResult, PoolTransaction, SubPoolLimit,
    TransactionPool, TransactionPoolExt, TransactionValidationTaskExecutor, ValidPoolTransaction,
};

use crate::db_provider::DbProvider;

/// The concrete implementation type for the Citrea mempool, using Reth's Pool with custom configuration
type CitreaMempoolImpl = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

/// Type alias for the transaction type used in the Citrea mempool
type Transaction = <CitreaMempoolImpl as TransactionPool>::Transaction;

/// An abstraction on top of Reth's mempool with custom Citrea functionality.
pub struct CitreaMempool(CitreaMempoolImpl);

impl CitreaMempool {
    /// Creates a new instance of the Citrea mempool.
    pub(crate) fn new(
        client: DbProvider,
        mempool_conf: SequencerMempoolConfig,
        task_executor: TaskExecutor,
    ) -> anyhow::Result<Self> {
        let blob_store = NoopBlobStore::default();

        let evm_config = client.cfg();

        // Default 10x'ed from standard limits
        let pool_config = PoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: mempool_conf.pending_tx_limit as usize,
                max_size: (mempool_conf.pending_tx_size * 1024 * 1024) as usize,
            },
            basefee_limit: SubPoolLimit {
                max_txs: mempool_conf.base_fee_tx_limit as usize,
                max_size: (mempool_conf.base_fee_tx_size * 1024 * 1024) as usize,
            },
            queued_limit: SubPoolLimit {
                max_txs: mempool_conf.queue_tx_limit as usize,
                max_size: (mempool_conf.queue_tx_size * 1024 * 1024) as usize,
            },
            blob_limit: SubPoolLimit {
                max_txs: 0,
                max_size: 0,
            },
            max_account_slots: mempool_conf.max_account_slots as usize,
            minimal_protocol_basefee: MIN_BASE_FEE_PER_GAS,
            ..Default::default()
        };

        let validator = TransactionValidationTaskExecutor::eth_builder(client)
            .no_eip4844()
            .set_shanghai(true)
            .set_cancun(true)
            .set_prague(true)
            // TODO: if we ever increase block gas limits, we need to pull this from
            // somewhere else
            .set_block_gas_limit(evm_config.block_gas_limit)
            .build_with_tasks::<EthPooledTransaction, _, _>(task_executor, blob_store);

        Ok(Self(Pool::eth_pool(validator, blob_store, pool_config)))
    }

    /// Add a transaction to the mempool
    pub(crate) async fn add_external_transaction(
        &self,
        transaction: EthPooledTransaction,
    ) -> PoolResult<TxHash> {
        if transaction.transaction().signer() == SYSTEM_SIGNER {
            return Err(PoolError::other(
                *transaction.hash(),
                "system transactions from rpc are not allowed",
            ));
        }

        if transaction.transaction().is_eip4844() {
            return Err(PoolError::new(
                *transaction.hash(),
                PoolErrorKind::InvalidTransaction(
                    reth_transaction_pool::error::InvalidPoolTransactionError::Consensus(
                        reth_primitives::InvalidTransactionError::Eip4844Disabled,
                    ),
                ),
            ));
        }

        self.0.add_external_transaction(transaction).await
    }

    /// Find and return a transaction by hash
    pub(crate) fn get(&self, hash: &TxHash) -> Option<Arc<ValidPoolTransaction<Transaction>>> {
        self.0.get(hash)
    }

    /// Remove a transaction from mempool.
    pub(crate) fn remove_transactions(
        &self,
        tx_hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Transaction>>> {
        self.0.remove_transactions(tx_hashes)
    }

    /// Performs account updates on the pool.
    ///
    /// This will either promote or discard transactions based on the new account state.
    pub(crate) fn update_accounts(&self, account_updates: Vec<ChangedAccount>) {
        self.0.update_accounts(account_updates);
    }

    /// Gets the best transactions from the mempool with specific attributes
    ///
    /// # Arguments
    /// * `best_transactions_attributes` - Attributes to consider when selecting transactions
    ///
    /// # Returns
    /// A boxed iterator of valid pool transactions
    pub(crate) fn best_transactions_with_attributes(
        &self,
        best_transactions_attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Transaction>>>> {
        self.0
            .best_transactions_with_attributes(best_transactions_attributes)
    }

    /// Gets the total number of transactions in the mempool
    ///
    /// # Returns
    /// The number of transactions currently in the pool
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}
