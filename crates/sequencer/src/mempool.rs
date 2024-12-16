use std::sync::Arc;

use anyhow::{anyhow, bail};
use citrea_common::SequencerMempoolConfig;
use citrea_evm::SYSTEM_SIGNER;
use reth_chainspec::{Chain, ChainSpecBuilder};
use reth_primitives::{Genesis, TxHash};
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::error::PoolError;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, ChangedAccount, CoinbaseTipOrdering,
    EthPooledTransaction, EthTransactionValidator, Pool, PoolConfig, PoolResult, SubPoolLimit,
    TransactionPool, TransactionPoolExt, TransactionValidationTaskExecutor, ValidPoolTransaction,
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
    pub(crate) fn new(
        client: DbProvider<C>,
        mempool_conf: SequencerMempoolConfig,
    ) -> anyhow::Result<Self> {
        let blob_store = NoopBlobStore::default();
        let genesis_block = client
            .genesis_block()
            .map(|b| b.ok_or(anyhow!("Genesis block does not exist")))
            .map_err(|e| anyhow!("{e}"))??;
        let evm_config = client.cfg();
        let Some(nonce) = genesis_block.header.nonce else {
            bail!("Genesis nonce is not set");
        };
        let Some(genesis_mix_hash) = genesis_block.header.mix_hash else {
            bail!("Genesis mix_hash is not set");
        };
        let chain_spec = ChainSpecBuilder::default()
            .chain(Chain::from_id(evm_config.chain_id))
            .shanghai_activated()
            .genesis(
                Genesis::default()
                    .with_nonce(nonce.into())
                    .with_timestamp(genesis_block.header.timestamp)
                    .with_extra_data(genesis_block.header.extra_data)
                    .with_gas_limit(genesis_block.header.gas_limit)
                    .with_difficulty(genesis_block.header.difficulty)
                    .with_mix_hash(genesis_mix_hash)
                    .with_coinbase(genesis_block.header.miner)
                    .with_base_fee(genesis_block.header.base_fee_per_gas),
            )
            .build();

        // Default 10x'ed from standard limits
        let pool_config = Default::default();
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
            ..pool_config
        };

        let validator = TransactionValidationTaskExecutor::eth_builder(Arc::new(chain_spec))
            .no_cancun()
            .no_eip4844()
            // TODO: if we ever increase block gas limits, we need to pull this from
            // somewhere else
            .set_block_gas_limit(evm_config.block_gas_limit)
            .set_shanghai(true)
            .with_additional_tasks(0)
            .build_with_tasks(client, TokioTaskExecutor::default(), blob_store);

        Ok(Self(Pool::eth_pool(validator, blob_store, pool_config)))
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

    pub(crate) fn update_accounts(&self, account_updates: Vec<ChangedAccount>) {
        self.0.update_accounts(account_updates);
    }

    pub(crate) fn best_transactions_with_attributes(
        &self,
        best_transactions_attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Transaction<C>>>>> {
        self.0
            .best_transactions_with_attributes(best_transactions_attributes)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}
