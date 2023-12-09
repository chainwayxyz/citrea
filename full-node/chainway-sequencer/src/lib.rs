#[cfg(feature = "experimental")]
pub use sov_evm::DevSigner;

#[cfg(feature = "experimental")]
pub mod experimental {
    use std::array::TryFromSliceError;
    use std::borrow::BorrowMut;
    use std::collections::VecDeque;
    use std::marker::PhantomData;
    use std::net::SocketAddr;
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::Arc;
    use std::time::Duration;

    use borsh::ser::BorshSerialize;
    use demo_stf::runtime::Runtime;
    use ethers::types::{Bytes, H256};
    use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
    use futures::lock::Mutex;
    // socketaddr
    use futures::StreamExt;
    use futures::{select, AsyncBufReadExt, Stream};
    use jsonrpsee::types::ErrorObjectOwned;
    use jsonrpsee::RpcModule;
    use reth_primitives::TransactionSignedNoHash as RethTransactionSignedNoHash;
    use sov_evm::{CallMessage, Evm, RlpEvmTransaction};
    use sov_modules_api::transaction::Transaction;
    use sov_modules_api::{DaSpec, EncodeCall, PrivateKey, WorkingSet};
    use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
    use sov_modules_stf_blueprint::{Batch, RawTx};
    use sov_rollup_interface::services::da::DaService;
    use tokio::sync::oneshot;
    use tracing::{debug, info};
    const ETH_RPC_ERROR: &str = "ETH_RPC_ERROR";

    // create a mpsc channel give producer to eth_publishBatch
    // give consumer to process function
    // if a call comes to eth_publishBatch, send it to process function
    // with that the block shall be made
    #[derive(Clone)]
    pub struct SequencerRpcConfig<C: sov_modules_api::Context> {
        pub min_blob_size: Option<usize>,
        pub sov_tx_signer_priv_key: C::PrivateKey,
    }

    struct Mempool {
        pool: VecDeque<RlpEvmTransaction>,
    }

    impl Mempool {
        pub fn new() -> Self {
            Mempool {
                pool: VecDeque::new(),
            }
        }
    }

    // pub fn get_sequencer_rpc<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint>(
    //     rollup: Rollup<S>,
    //     da_service: Da,
    //     eth_rpc_config: SequencerRpcConfig<C>,
    //     storage: C::Storage,
    // ) -> RpcModule<ChainwaySequencer<C, Da, S>> {
    //     // Unpack config
    //     let SequencerRpcConfig {
    //         min_blob_size,
    //         sov_tx_signer_priv_key,
    //     } = eth_rpc_config;

    //     // Fetch nonce from storage
    //     let accounts = sov_accounts::Accounts::<C>::default();
    //     let sov_tx_signer_account = accounts
    //         .get_account(
    //             sov_tx_signer_priv_key.pub_key(),
    //             &mut WorkingSet::<C>::new(storage.clone()),
    //         )
    //         .unwrap();
    //     let sov_tx_signer_nonce: u64 = match sov_tx_signer_account {
    //         sov_accounts::Response::AccountExists { nonce, .. } => nonce,
    //         sov_accounts::Response::AccountEmpty { .. } => 0,
    //     };

    //     let mut rpc = RpcModule::new(ChainwaySequencer::new(
    //         rollup,
    //         da_service,
    //         sov_tx_signer_priv_key,
    //         sov_tx_signer_nonce,
    //     ));

    //     register_rpc_methods(&mut rpc).expect("Failed to register sequencer RPC methods");
    //     rpc
    // }

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
            let evm = Evm::<C>::default();
            let mempool = Mempool::new();
            let (sender, receiver) = unbounded();

            let mempool = Mempool::new();

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

        pub async fn run(
            &mut self,
            channel: oneshot::Sender<SocketAddr>,
        ) -> Result<(), anyhow::Error> {
            println!("7");
            self.rollup
                .runner
                .start_rpc_server(self.rollup.rpc_methods.clone(), Some(channel))
                .await;
            println!("8");

            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;

                if let Ok(Some(resp)) = self.receiver.try_next() {
                    println!("9");
                    let mut rlp_txs = vec![];
                    // TODO: Open an issue about a better batch building algorithm
                    let mut mem = self.mempool.lock().await;
                    while !mem.pool.is_empty() && rlp_txs.len() < 5 {
                        // TODO: Handle error
                        rlp_txs.push(mem.pool.pop_front().unwrap());
                    }
                    core::mem::drop(mem);

                    if rlp_txs.is_empty() {
                        continue;
                    }

                    println!("txs from mempool: {:?}", rlp_txs);

                    info!("evm txs count: {}", rlp_txs.len());

                    info!("these txs are: {:?}", rlp_txs);
                    //batch_txs.push()
                    // let rlp_txs = batch_txs
                    //     .iter()
                    //     .map(|x| RlpEvmTransaction { rlp: x.clone() })
                    //     .collect();

                    let call_txs = CallMessage { txs: rlp_txs };
                    let raw_message =
                        <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(
                            call_txs,
                        );
                    let signed_blob = self.make_blob(raw_message);

                    let batch = Batch {
                        txs: vec![RawTx {
                            data: signed_blob.clone(),
                        }],
                    };
                    // let hash = self.da_service.hash_blob(signed_blob.as_slice()).unwrap();
                    // let mut blobz = self
                    //     .da_service
                    //     .convert_to_transaction(signed_blob.as_slice(), hash)
                    //     .unwrap();
                    // self.rollup.lock().unwrap().runner.process(&mut blobz.0);

                    // TODO: Handle error
                    self.rollup
                        .runner
                        .process(&batch.try_to_vec().unwrap())
                        .await?;
                    println!("processedddddd");
                    // if no error save blob to ledger db
                }
            }

            Ok(())
        }

        // fn add_tx(&self, tx: Vec<u8>) {
        //     self.mempool.lock().unwrap().push_back(tx);
        // }

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
            let mut rpc = RpcModule::new((self.mempool.clone(), sc_sender));
            rpc.register_async_method(
                "eth_sendRawTransaction",
                |parameters, mempool| async move {
                    let data: Bytes = parameters.one().unwrap();

                    let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };

                    let h = get_tx_hash(&raw_evm_tx).unwrap();

                    // I hade to make mempool arc mutex because otherwise I could not mutate chainway sequencer
                    mempool.0.lock().await.pool.push_back(raw_evm_tx);
                    println!("MEMPOOL: {:?}", mempool.0.lock().await.pool);

                    Ok::<H256, ErrorObjectOwned>(h)
                },
            )?;
            // let sc_sender = self.sender.clone();
            rpc.register_async_method("eth_publishBatch", |parameters, mempool| async move {
                //     sc_sender.unbounded_send("a".to_string()).unwrap();
                println!("PUBLISHING BATCH");
                mempool.1.unbounded_send("msg".to_string()).unwrap();
                Ok::<(), ErrorObjectOwned>(())
            })?;
            self.rollup.rpc_methods.merge(rpc).unwrap();
            Ok(())
        }
    }

    fn get_tx_hash(raw_tx: &RlpEvmTransaction) -> Result<H256, jsonrpsee::core::Error> {
        let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

        let tx_hash = signed_transaction.hash();

        tx_hash;
    }

    // fn register_rpc_methods<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint>(
    //     rpc: &mut RpcModule<ChainwaySequencer<C, Da, S>>,
    // ) -> Result<(), jsonrpsee::core::Error> {
    //     // rpc.register_async_method(
    //     //     "eth_sendRawTransaction",
    //     //     |parameters, chainway_sequencer| async move {
    //     //         let data: Bytes = parameters.one().unwrap();

    //     //         let raw_evm_tx = RlpEvmTransaction { rlp: data.to_vec() };
    //     //         // I hade to make mempool arc mutex because otherwise I could not mutate chainway sequencer
    //     //         chainway_sequencer.add_tx(raw_evm_tx.rlp);

    //     //         Ok::<_, ErrorObjectOwned>(data)
    //     //     },
    //     // )?;
    //     // // Query sov-txs in state
    //     // rpc.register_async_method(
    //     //     "cw_getSoftConfirmation",
    //     //     |parameters, chainway_sequencer| async move { Ok::<_, ErrorObjectOwned>(()) },
    //     // )?;
    //     Ok(())
    // }
    fn get_tx_hash(raw_tx: &RlpEvmTransaction) -> Result<H256, jsonrpsee::core::Error> {
        let signed_transaction: RethTransactionSignedNoHash = raw_tx.clone().try_into()?;

        let tx_hash = signed_transaction.hash();

        Ok(H256::from(tx_hash))
    }
}
