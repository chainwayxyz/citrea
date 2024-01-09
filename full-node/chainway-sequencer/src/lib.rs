use futures::StreamExt;
pub use sov_evm::DevSigner;
pub mod db_provider;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_stf_runner::BlockTemplate;
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
use sov_modules_api::{EncodeCall, Module, PrivateKey, SlotData, WorkingSet};
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
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
    da_service: Da,
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
            da_service,
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
            if (self.receiver.next().await).is_some() {
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

                let prev_l1_height = self
                    .rollup
                    .runner
                    .get_head_soft_batch()?
                    .map(|(_, sb)| sb.da_slot_height)
                    .unwrap_or(1); // If this is the first block, then the previous block is the genesis block, may need revisiting

                let previous_l1_block = self.da_service.get_block_at(prev_l1_height).await.unwrap();

                let last_finalized_height = self
                    .da_service
                    .get_last_finalized_block_header()
                    .await
                    .unwrap()
                    .height();

                let last_finalized_block = self
                    .da_service
                    .get_block_at(last_finalized_height)
                    .await
                    .unwrap();

                // Compare if there is no skip
                if last_finalized_block.header().prev_hash() != previous_l1_block.header().hash() {
                    // TODO: This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                }

                if last_finalized_height != prev_l1_height {
                    // TODO: this is where we would include forced transactions from the new L1 block
                }

                let block_template = BlockTemplate {
                    da_slot_height: last_finalized_block.header().height(),
                    txs: vec![signed_blob],
                };

                // TODO: handle error
                self.rollup.runner.process(block_template).await?;
            }
        }
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(&mut self, raw_message: Vec<u8>) -> Vec<u8> {
        let nonce = self.sov_tx_signer_nonce.borrow_mut();

        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit
        let raw_tx = Transaction::<C>::new_signed_tx(
            &self.sov_tx_signer_priv_key,
            raw_message,
            0,
            0,
            0,
            *nonce,
        )
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
