pub use sov_evm::DevSigner;
mod mempool;

use std::array::TryFromSliceError;
use std::borrow::BorrowMut;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use borsh::ser::BorshSerialize;
use demo_stf::runtime::Runtime;
use ethers::types::{Bytes, H256};
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::lock::Mutex;
use futures::{select, AsyncBufReadExt, Stream, StreamExt};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use mempool::Mempool;
use reth_primitives::TransactionSignedNoHash as RethTransactionSignedNoHash;
use sov_evm::{CallMessage, Evm, RlpEvmTransaction};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::EncodeCall;
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_modules_stf_blueprint::{Batch, RawTx};
use sov_rollup_interface::services::da::DaService;
use tokio::sync::oneshot;
use tracing::{debug, info};

const ETH_RPC_ERROR: &str = "ETH_RPC_ERROR";

pub struct RpcContext {
    pub mempool: Arc<Mutex<Mempool>>,
    pub sender: UnboundedSender<String>,
}

pub struct ChainwaySequencer<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> {
    rollup: Rollup<S>,
    da_service: Da,
    mempool: Arc<Mutex<Mempool>>,
    p: PhantomData<C>,
    sov_tx_signer_priv_key: C::PrivateKey,
    sov_tx_signer_nonce: u64,
    sender: UnboundedSender<String>,
    receiver: UnboundedReceiver<String>,
}

impl<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> ChainwaySequencer<C, Da, S> {
    pub fn new(
        rollup: Rollup<S>,
        da_service: Da,
        sov_tx_signer_priv_key: C::PrivateKey,
        sov_tx_signer_nonce: u64,
    ) -> Self {
        let mempool = Mempool::new();
        let (sender, receiver) = unbounded();

        Self {
            rollup,
            da_service,
            mempool: Arc::new(Mutex::new(mempool)),
            p: PhantomData,
            sov_tx_signer_priv_key,
            sov_tx_signer_nonce,
            sender,
            receiver,
        }
    }

    fn make_raw_tx(
        &self,
        raw_tx: RlpEvmTransaction,
    ) -> Result<(H256, Vec<u8>), jsonrpsee::core::Error> {
        let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

        let tx_hash = signed_transaction.hash();

        let tx = CallMessage { txs: vec![raw_tx] };
        let message = <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(tx);

        Ok((H256::from(tx_hash), message))
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
            tokio::time::sleep(Duration::from_millis(100)).await;

            if let Ok(Some(resp)) = self.receiver.try_next() {
                let mut rlp_txs = vec![];
                let mut mem = self.mempool.lock().await;
                while !mem.pool.is_empty() {
                    // TODO: Handle error
                    rlp_txs.push(mem.pool.pop_front().unwrap());
                }
                core::mem::drop(mem);

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
            info!("Sequencer: eth_sendRawTransaction");
            let data: Bytes = parameters.one().unwrap();

            let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };

            let hash = get_tx_hash(&raw_evm_tx).unwrap();

            // Mempool had to be arc mutex to mutate chainway sequencer
            ctx.mempool.lock().await.pool.push_back(raw_evm_tx);

            Ok::<H256, ErrorObjectOwned>(hash)
        })?;
        rpc.register_async_method("eth_publishBatch", |parameters, ctx| async move {
            info!("Sequencer: eth_publishBatch");
            ctx.sender.unbounded_send("msg".to_string()).unwrap();
            Ok::<(), ErrorObjectOwned>(())
        })?;
        self.rollup.rpc_methods.merge(rpc).unwrap();
        Ok(())
    }
}

fn get_tx_hash(raw_tx: &RlpEvmTransaction) -> Result<H256, jsonrpsee::core::Error> {
    let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

    let tx_hash = signed_transaction.hash();

    Ok(H256::from(tx_hash))
}
