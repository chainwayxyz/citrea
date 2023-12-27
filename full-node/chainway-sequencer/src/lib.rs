use futures::StreamExt;
pub use sov_evm::DevSigner;
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
use reth_primitives::Bytes;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_evm::{CallMessage, RlpEvmTransaction};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{EncodeCall, PrivateKey, WorkingSet};
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_modules_stf_blueprint::{Batch, RawTx};
use sov_rollup_interface::services::da::DaService;
use tracing::info;

use crate::utils::recover_raw_transaction;

pub struct RpcContext {
    pub mempool: Arc<Mutex<Mempool>>,
    pub sender: UnboundedSender<String>,
}

pub struct ChainwaySequencer<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> {
    rollup: Rollup<S>,
    // not used for now, will probably need it later
    _da_service: Da,
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

        Self {
            rollup,
            _da_service: da_service,
            mempool: Arc::new(Mutex::new(mempool)),
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

            // Only check if the signature is valid for now
            let recovered = recover_raw_transaction(data.clone())?;

            // TODO: make mempool conversions once it is implemented
            // Follow the example of eth_sendRawTransaction in reth
            // https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/api/transactions.rs#L505

            let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };

            // Mempool had to be arc mutex to mutate chainway sequencer
            ctx.mempool.lock().await.pool.push_back(raw_evm_tx);

            Ok::<H256, ErrorObjectOwned>((*recovered.hash()).into())
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
