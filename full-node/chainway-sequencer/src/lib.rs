use futures::StreamExt;
pub use sov_evm::DevSigner;
pub mod db_provider;
mod mempool;
mod utils;

use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use borsh::ser::BorshSerialize;
use demo_stf::runtime::Runtime;
use ethers::types::H256;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::lock::Mutex;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use mempool::Mempool;
use reth_primitives::{Bytes, FromRecoveredPooledTransaction, IntoRecoveredTransaction, MAINNET};
use reth_provider::{BlockReaderIdExt, ChainSpecProvider, StateProviderFactory};
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::{
    CoinbaseTipOrdering, EthPooledTransaction, EthTransactionValidator, Pool, TransactionOrigin,
    TransactionPool, TransactionValidationTaskExecutor,
};
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_evm::{CallMessage, RlpEvmTransaction};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{EncodeCall, Module, PrivateKey, WorkingSet};
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_modules_stf_blueprint::{Batch, RawTx};
use sov_rollup_interface::services::da::DaService;
use tracing::info;

pub use crate::db_provider::DbProvider;
use crate::utils::recover_raw_transaction;

type CitreaMempool<C: sov_modules_api::Context> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider<C>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

fn create_mempool<C>(
    client: C,
) -> Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<C, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>
where
    C: StateProviderFactory + BlockReaderIdExt + ChainSpecProvider + Clone + 'static,
{
    let blob_store = NoopBlobStore::default();
    Pool::eth_pool(
        TransactionValidationTaskExecutor::eth(
            client,
            MAINNET.clone(),
            blob_store.clone(),
            TokioTaskExecutor::default(),
        ),
        blob_store,
        Default::default(),
    )
}

pub struct RpcContext<C: sov_modules_api::Context> {
    pub mempool: Arc<CitreaMempool<C>>,
    pub sender: UnboundedSender<String>,
}

pub struct ChainwaySequencer<
    C: sov_modules_api::Context,
    Da: DaService,
    S: RollupBlueprint,
    Pool: TransactionPool + Clone + 'static,
> {
    rollup: Rollup<S>,
    // not used for now, will probably need it later
    _da_service: Da,
    mempool: Arc<CitreaMempool<C>>,
    p: PhantomData<(C, Pool)>,
    sov_tx_signer_priv_key: C::PrivateKey,
    sov_tx_signer_nonce: u64,
    sender: UnboundedSender<String>,
    receiver: UnboundedReceiver<String>,
}

impl<
        C: sov_modules_api::Context,
        Da: DaService,
        S: RollupBlueprint,
        Pool: TransactionPool + Clone + 'static,
    > ChainwaySequencer<C, Da, S, Pool>
{
    pub fn new(
        rollup: Rollup<S>,
        da_service: Da,
        sov_tx_signer_priv_key: C::PrivateKey,
        storage: C::Storage,
    ) -> Self {
        let mempool = Mempool::new();
        let (sender, receiver) = unbounded();

        let accounts = Accounts::<C>::default();
        let mut working_set = WorkingSet::<C>::new(storage.clone());
        let nonce = match accounts
            .get_account(sov_tx_signer_priv_key.pub_key(), &mut working_set)
            .expect("Sequencer: Failed to get sov-account")
        {
            AccountExists { addr: _, nonce } => nonce,
            AccountEmpty => 0,
        };

        // used as client of reth's mempool
        let db_provider = DbProvider::new(storage);

        let pool = create_mempool(db_provider);
        // pool.add_transaction(origin, transaction)

        Self {
            rollup,
            _da_service: da_service,
            mempool: Arc::new(pool),
            p: PhantomData,
            sov_tx_signer_priv_key,
            sov_tx_signer_nonce: nonce,
            sender,
            receiver,
        }
    }

    pub async fn start_rpc_server(
        &mut self,
        channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
    ) -> Result<(), anyhow::Error> {
        self.register_rpc_methods()?;

        self.rollup
            .runner
            .start_rpc_server(self.rollup.rpc_methods.clone(), channel)
            .await;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        loop {
            if let Some(_) = self.receiver.next().await {
                let mut rlp_txs = vec![];

                while !self.mempool.is_empty() {
                    // TODO: Handle error
                    let best_txs = self.mempool.best_transactions();
                    // TODO: Handle block building
                    for tx in best_txs {
                        let rc_tx = tx.to_recovered_transaction();
                        let signed_tx = rc_tx.into_signed();
                        let x = signed_tx.envelope_encoded().to_vec();

                        rlp_txs.push(RlpEvmTransaction { rlp: x });
                        self.mempool.remove_transactions(vec![*tx.hash()]);
                    }
                }

                info!(
                    "Sequencer: publishing block with {} transactions",
                    rlp_txs.len()
                );

                let call_txs = CallMessage { txs: rlp_txs };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(call_txs);
                let signed_blob = self.make_blob(raw_message);

                let batch = Batch {
                    txs: vec![RawTx {
                        data: signed_blob.clone(),
                    }],
                };

                // TODO: Handle error
                self.rollup
                    .runner
                    .process(&batch.try_to_vec().unwrap())
                    .await?;
            }
        }

        Ok(())
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(&mut self, raw_message: Vec<u8>) -> Vec<u8> {
        let nonce = self.sov_tx_signer_nonce.borrow_mut();

        let raw_tx =
            Transaction::<C>::new_signed_tx(&self.sov_tx_signer_priv_key, raw_message, *nonce)
                .try_to_vec()
                .unwrap();

        *nonce += 1;

        raw_tx
    }

    pub fn register_rpc_methods(&mut self) -> Result<(), jsonrpsee::core::Error> {
        let sc_sender = self.sender.clone();
        let rpc_context = RpcContext {
            mempool: self.mempool.clone(),
            sender: sc_sender.clone(),
        };
        let mut rpc = RpcModule::new(rpc_context);
        rpc.register_async_method("eth_sendRawTransaction", |parameters, ctx| async move {
            // https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/api/transactions.rs#L505
            info!("Sequencer: eth_sendRawTransaction");
            let data: Bytes = parameters.one().unwrap();

            // Only check if the signature is valid for now
            let recovered: reth_primitives::PooledTransactionsElementEcRecovered =
                recover_raw_transaction(data.clone())?;

            let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };

            // TODO: fn should be named from_recoverd_pooled_transaction after reth upgrade
            let pool_transaction =
                EthPooledTransaction::from_recovered_transaction(recovered.clone());
            println!("pool_transaction: {:?}", pool_transaction);

            // submit the transaction to the pool with a `Local` origin
            let hash = ctx
                .mempool
                .add_transaction(TransactionOrigin::Local, pool_transaction)
                .await
                .unwrap();
            Ok::<H256, ErrorObjectOwned>(H256::from_slice(hash.as_bytes()))
        })?;
        rpc.register_async_method("eth_publishBatch", |_, ctx| async move {
            info!("Sequencer: eth_publishBatch");
            ctx.sender.unbounded_send("msg".to_string()).unwrap();
            Ok::<(), ErrorObjectOwned>(())
        })?;
        self.rollup.rpc_methods.merge(rpc).unwrap();
        Ok(())
    }
}
