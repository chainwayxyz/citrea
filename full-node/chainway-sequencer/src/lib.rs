pub mod db_provider;
mod utils;

use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec;

use borsh::ser::BorshSerialize;
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use reth_primitives::{
    BaseFeeParamsKind, Bytes, Chain, ChainSpec, FromRecoveredPooledTransaction,
    IntoRecoveredTransaction, B256,
};
use reth_provider::BlockReaderIdExt;
use reth_rpc_types_compat::transaction::from_recovered;
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::{
    CoinbaseTipOrdering, EthPooledTransaction, EthTransactionValidator, Pool, TransactionOrigin,
    TransactionPool, TransactionValidationTaskExecutor,
};
use soft_confirmation_rule_enforcer::CallMessage as ScCallMessage;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
pub use sov_evm::DevSigner;
use sov_evm::{CallMessage, Evm, RlpEvmTransaction};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::{
    EncodeCall, PrivateKey, SignedSoftConfirmationBatch, SlotData, UnsignedSoftConfirmationBatch,
    WorkingSet,
};
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_modules_stf_blueprint::ApplySoftConfirmationError;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use tracing::info;

pub use crate::db_provider::DbProvider;
use crate::utils::recover_raw_transaction;

type CitreaMempool<C> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider<C>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

const ETH_RPC_ERROR: &str = "ETH_RPC_ERROR";

fn create_mempool<C: sov_modules_api::Context>(client: DbProvider<C>) -> CitreaMempool<C> {
    let blob_store = NoopBlobStore::default();
    let genesis_hash = client.genesis_block().unwrap().unwrap().header.hash;
    let evm_config = client.cfg();
    let chain_spec = ChainSpec {
        chain: Chain::from_id(evm_config.chain_id),
        genesis_hash,
        base_fee_params: BaseFeeParamsKind::Constant(evm_config.base_fee_params),
        ..Default::default()
    };
    Pool::eth_pool(
        TransactionValidationTaskExecutor::eth(
            client,
            Arc::new(chain_spec),
            blob_store,
            TokioTaskExecutor::default(),
        ),
        blob_store,
        Default::default(),
    )
}

pub struct RpcContext<C: sov_modules_api::Context> {
    pub mempool: Arc<CitreaMempool<C>>,
    pub sender: UnboundedSender<String>,
    pub storage: C::Storage,
}

pub struct ChainwaySequencer<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> {
    rollup: Rollup<S>,
    da_service: Da,
    mempool: Arc<CitreaMempool<C>>,
    p: PhantomData<C>,
    sov_tx_signer_priv_key: C::PrivateKey,
    sov_tx_signer_nonce: u64,
    sender: UnboundedSender<String>,
    receiver: UnboundedReceiver<String>,
    db_provider: DbProvider<C>,
    storage: C::Storage,
}

impl<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> ChainwaySequencer<C, Da, S> {
    pub fn new(
        rollup: Rollup<S>,
        da_service: Da,
        sov_tx_signer_priv_key: C::PrivateKey,
        storage: C::Storage,
    ) -> Self {
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
        let db_provider = DbProvider::new(storage.clone());

        let pool = create_mempool(db_provider.clone());

        Self {
            rollup,
            da_service,
            mempool: Arc::new(pool),
            p: PhantomData,
            sov_tx_signer_priv_key,
            sov_tx_signer_nonce: nonce,
            sender,
            receiver,
            db_provider,
            storage,
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
                // best txs with base fee
                // get base fee from last blocks => header => next base fee() function
                let cfg: sov_evm::EvmChainConfig = self.db_provider.cfg();

                let base_fee = self
                    .db_provider
                    .latest_header()
                    .expect("Failed to get latest header")
                    .map(|header| header.unseal().next_block_base_fee(cfg.base_fee_params))
                    .expect("Failed to get next block base fee")
                    .unwrap();

                let best_txs_with_base_fee = self.mempool.best_transactions_with_base_fee(base_fee);

                // TODO: implement block builder instead of just including every transaction in order
                let rlp_txs: Vec<RlpEvmTransaction> = best_txs_with_base_fee
                    .into_iter()
                    .map(|tx| {
                        tx.to_recovered_transaction()
                            .into_signed()
                            .envelope_encoded()
                            .to_vec()
                    })
                    .map(|rlp| RlpEvmTransaction { rlp })
                    .collect();

                info!(
                    "Sequencer: publishing block with {} transactions",
                    rlp_txs.len()
                );

                let call_txs = CallMessage { txs: rlp_txs };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(call_txs);
                let signed_blob = self.make_blob(raw_message);

                let sc_call_txs: soft_confirmation_rule_enforcer::CallMessage<C> =
                    ScCallMessage::ModifyLimitingNumber {
                        limiting_number: 15,
                    };
                let sc_raw_message = <Runtime<C, Da::Spec> as EncodeCall<
                    soft_confirmation_rule_enforcer::SoftConfirmationRuleEnforcer<C, Da::Spec>,
                >>::encode_call(sc_call_txs);
                let sc_signed_blob = self.make_blob(sc_raw_message);

                let prev_l1_height = self
                    .rollup
                    .runner
                    .get_head_soft_batch()?
                    .map(|(_, sb)| sb.da_slot_height)
                    // TODO: default to starting height
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

                let l1_fee_rate = self.da_service.get_fee_rate().await.unwrap();

                // Compare if there is no skip
                if last_finalized_block.header().prev_hash() != previous_l1_block.header().hash() {
                    // TODO: This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                }

                if last_finalized_height != prev_l1_height {
                    // TODO: this is where we would include forced transactions from the new L1 block
                }

                let batch_info = HookSoftConfirmationInfo {
                    da_slot_height: last_finalized_block.header().height(),
                    da_slot_hash: last_finalized_block.header().hash().into(),
                    pre_state_root: self
                        .rollup
                        .runner
                        .get_state_root()
                        .clone()
                        .as_ref()
                        .to_vec(),
                    pub_key: self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
                    l1_fee_rate,
                };
                let mut signed_batch = batch_info.clone().into();
                // initially create sc info and call begin soft confirmation hook with it
                let txs = vec![signed_blob.clone()];
                match self
                    .rollup
                    .runner
                    .begin_soft_confirmation(&mut signed_batch)
                    .await
                {
                    (Ok(()), batch_workspace) => {
                        let (_sequencer_reward, batch_workspace, tx_receipts) = self
                            .rollup
                            .runner
                            .apply_sov_tx(txs.clone(), batch_workspace)
                            .await;

                        let sc_txs = vec![sc_signed_blob.clone()];
                        let (sequencer_reward, batch_workspace, sc_tx_receipts) = self
                            .rollup
                            .runner
                            .apply_sov_tx(sc_txs.clone(), batch_workspace)
                            .await;
                        let mut all_txs = vec![];
                        all_txs.extend(txs);
                        all_txs.extend(sc_txs);
                        let mut all_receipts = vec![];
                        all_receipts.extend(tx_receipts);
                        all_receipts.extend(sc_tx_receipts);

                        let unsigned_batch = UnsignedSoftConfirmationBatch {
                            da_slot_height: last_finalized_block.header().height(),
                            txs: all_txs,
                            da_slot_hash: last_finalized_block.header().hash().into(),
                            pre_state_root: self
                                .rollup
                                .runner
                                .get_state_root()
                                .clone()
                                .as_ref()
                                .to_vec(),
                            l1_fee_rate,
                        };

                        // create the unsigned batch with the txs then sign th sc

                        let mut signed_soft_batch =
                            self.sign_soft_confirmation_batch(unsigned_batch);

                        let _ = self
                            .rollup
                            .runner
                            .end_soft_confirmation(
                                &mut signed_soft_batch,
                                sequencer_reward,
                                all_receipts,
                                batch_workspace,
                            )
                            .await;
                        self.mempool
                            .remove_transactions(self.db_provider.last_block_tx_hashes());
                    }
                    (
                        Err(ApplySoftConfirmationError::TooManySoftConfirmationsOnDaSlot {
                            hash: _,
                            sequencer_pub_key: _,
                        }),
                        batch_workspace,
                    ) => {
                        batch_workspace.revert();
                        // return SlotResult {
                        //     state_root: pre_state_root.clone(),
                        //     change_set: pre_state, // should be empty
                        //     batch_receipts: vec![],
                        //     witness: <<C as Spec>::Storage as Storage>::Witness::default(),
                        // };
                        // handle error?
                    }
                }

                // get txs and call apply tx with it

                // TODO: handle error
                // self.rollup.runner.process(signed_soft_batch).await?;

                // get last block remove only txs in block
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

    /// Signs necessary info and returns a BlockTemplate
    fn sign_soft_confirmation_batch(
        &mut self,
        soft_confirmation: UnsignedSoftConfirmationBatch,
    ) -> SignedSoftConfirmationBatch {
        let raw = soft_confirmation.try_to_vec().unwrap();

        let hash = <C as sov_modules_api::Spec>::Hasher::digest(raw.as_slice()).into();

        let signature = self.sov_tx_signer_priv_key.sign(&raw);

        SignedSoftConfirmationBatch {
            hash,
            da_slot_height: soft_confirmation.da_slot_height,
            txs: soft_confirmation.txs,
            da_slot_hash: soft_confirmation.da_slot_hash,
            pre_state_root: soft_confirmation.pre_state_root,
            pub_key: self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
            signature: signature.try_to_vec().unwrap(),
            l1_fee_rate: soft_confirmation.l1_fee_rate,
        }
    }

    pub fn register_rpc_methods(&mut self) -> Result<(), jsonrpsee::core::Error> {
        let sc_sender = self.sender.clone();
        let rpc_context = RpcContext {
            mempool: self.mempool.clone(),
            sender: sc_sender.clone(),
            storage: self.storage.clone(),
        };
        let mut rpc = RpcModule::new(rpc_context);
        rpc.register_async_method("eth_sendRawTransaction", |parameters, ctx| async move {
            info!("Sequencer: eth_sendRawTransaction");
            let data: Bytes = parameters.one().unwrap();

            // Only check if the signature is valid for now
            let recovered: reth_primitives::PooledTransactionsElementEcRecovered =
                recover_raw_transaction(data.clone())?;

            let pool_transaction =
                EthPooledTransaction::from_recovered_pooled_transaction(recovered);

            // submit the transaction to the pool with a `Local` origin
            let hash: B256 = ctx
                .mempool
                .add_transaction(TransactionOrigin::External, pool_transaction)
                .await
                .map_err(|e| to_jsonrpsee_error_object(e, ETH_RPC_ERROR))?;
            Ok::<B256, ErrorObjectOwned>(hash)
        })?;
        rpc.register_async_method("eth_publishBatch", |_, ctx| async move {
            info!("Sequencer: eth_publishBatch");
            ctx.sender.unbounded_send("msg".to_string()).unwrap();
            Ok::<(), ErrorObjectOwned>(())
        })?;
        rpc.register_async_method("eth_getTransactionByHash", |parameters, ctx| async move {
            let mut params = parameters.sequence();
            let hash: B256 = params.next().unwrap();
            let mempool_only: Result<Option<bool>, ErrorObjectOwned> = params.next();
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
                    Ok(Some(true)) => {
                        Ok::<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>(None)
                    }
                    _ => {
                        let evm = Evm::<C>::default();
                        let mut working_set = WorkingSet::<C>::new(ctx.storage.clone());

                        match evm.get_transaction_by_hash(hash, &mut working_set) {
                            Ok(tx) => {
                                Ok::<Option<reth_rpc_types::Transaction>, ErrorObjectOwned>(tx)
                            }
                            Err(e) => Err(to_jsonrpsee_error_object(e, ETH_RPC_ERROR)),
                        }
                    }
                },
            }
        })?;
        self.rollup.rpc_methods.merge(rpc).unwrap();
        Ok(())
    }
}
