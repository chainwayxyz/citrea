pub mod db_provider;
mod utils;

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

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
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::types::{BatchNumber, SlotNumber};
pub use sov_evm::DevSigner;
use sov_evm::{CallMessage, Evm, RlpEvmTransaction};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::utils::to_jsonrpsee_error_object;
use sov_modules_api::{
    EncodeCall, PrivateKey, SignedSoftConfirmationBatch, SlotData, UnsignedSoftConfirmationBatch,
    WorkingSet,
};
use sov_modules_rollup_blueprint::{Rollup, RollupBlueprint};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use tracing::{debug, info, warn};

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

pub struct SequencingParams {
    pub min_soft_confirmations_per_commitment: u64,
}

pub struct ChainwaySequencer<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> {
    rollup: Rollup<S>,
    da_service: Da,
    mempool: Arc<CitreaMempool<C>>,
    p: PhantomData<C>,
    sov_tx_signer_priv_key: C::PrivateKey,
    sender: UnboundedSender<String>,
    receiver: UnboundedReceiver<String>,
    db_provider: DbProvider<C>,
    storage: C::Storage,
    ledger_db: LedgerDB,
    params: SequencingParams,
}

impl<C: sov_modules_api::Context, Da: DaService, S: RollupBlueprint> ChainwaySequencer<C, Da, S> {
    pub fn new(
        rollup: Rollup<S>,
        da_service: Da,
        sov_tx_signer_priv_key: C::PrivateKey,
        storage: C::Storage,
        params: SequencingParams,
    ) -> Self {
        let (sender, receiver) = unbounded();

        // used as client of reth's mempool
        let db_provider = DbProvider::new(storage.clone());

        let pool = create_mempool(db_provider.clone());

        let ledger_db = rollup.runner.ledger_db.clone();

        Self {
            rollup,
            da_service,
            mempool: Arc::new(pool),
            p: PhantomData,
            sov_tx_signer_priv_key,
            sender,
            receiver,
            db_provider,
            storage,
            ledger_db,
            params,
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
        // TODO: hotfix for mock da
        self.da_service.get_block_at(1).await.unwrap();

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

                warn!(
                    "Sequencer: publishing block with {} transactions",
                    rlp_txs.len()
                );

                let call_txs = CallMessage { txs: rlp_txs };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<sov_evm::Evm<C>>>::encode_call(call_txs);
                let signed_blob = self.make_blob(raw_message);

                let mut prev_l1_height = self
                    .ledger_db
                    .get_head_soft_batch()?
                    .map(|(_, sb)| sb.da_slot_height);

                if prev_l1_height.is_none() {
                    prev_l1_height = Some(
                        self.da_service
                            .get_last_finalized_block_header()
                            .await
                            .unwrap()
                            .height(),
                    );
                }

                let prev_l1_height = prev_l1_height.unwrap();

                warn!("Sequencer: prev L1 height: {:?}", prev_l1_height);

                let last_finalized_height = self
                    .da_service
                    .get_last_finalized_block_header()
                    .await
                    .unwrap()
                    .height();

                warn!(
                    "Sequencer: last finalized height: {:?}",
                    last_finalized_height
                );

                let last_finalized_block = self
                    .da_service
                    .get_block_at(last_finalized_height)
                    .await
                    .unwrap();

                let l1_fee_rate = self.da_service.get_fee_rate().await.unwrap();

                if last_finalized_height != prev_l1_height {
                    let previous_l1_block =
                        self.da_service.get_block_at(prev_l1_height).await.unwrap();

                    warn!("previous_l1_block: {:#?}", previous_l1_block);

                    // Compare if there is no skip
                    if last_finalized_block.header().prev_hash()
                        != previous_l1_block.header().hash()
                    {
                        // TODO: This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                    }
                    debug!("Sequencer: new L1 block, checking if commitment should be submitted");

                    // first get when the last merkle root of soft confirmations was submitted
                    let last_commitment_l1_height = self
                        .ledger_db
                        .get_last_sequencer_commitment_l1_height()
                        .expect("Sequencer: Failed to get last sequencer commitment L1 height");

                    warn!("Last commitment L1 height: {:?}", last_commitment_l1_height);
                    let mut l2_range_to_submit = None;
                    let mut _l1_height_range = None;
                    // if none then we never submitted a commitment, start from prev_l1_height and go back as far as you can go
                    // if there is a height then start from height + 1 and go to prev_l1_height
                    match last_commitment_l1_height {
                        Some(height) => {
                            let mut l1_height = height.0 + 1;

                            _l1_height_range = Some((l1_height, l1_height));

                            while let Some(l2_height_range) = self
                                .ledger_db
                                .get_l1_l2_connection(SlotNumber(l1_height))
                                .expect("Sequencer: Failed to get L1 L2 connection")
                            {
                                if l2_range_to_submit.is_none() {
                                    l2_range_to_submit = Some(l2_height_range);
                                } else {
                                    l2_range_to_submit =
                                        Some((l2_range_to_submit.unwrap().0, l2_height_range.1));
                                }

                                l1_height += 1;
                            }

                            _l1_height_range = Some((_l1_height_range.unwrap().0, l1_height - 1));
                        }
                        None => {
                            let mut l1_height = prev_l1_height;

                            _l1_height_range = Some((prev_l1_height, prev_l1_height));

                            while let Some(l2_height_range) = self
                                .ledger_db
                                .get_l1_l2_connection(SlotNumber(l1_height))
                                .expect("Sequencer: Failed to get L1 L2 connection")
                            {
                                if l2_range_to_submit.is_none() {
                                    l2_range_to_submit = Some(l2_height_range);
                                } else {
                                    l2_range_to_submit =
                                        Some((l2_height_range.0, l2_range_to_submit.unwrap().1));
                                }

                                l1_height -= 1;
                            }

                            _l1_height_range = Some((l1_height + 1, _l1_height_range.unwrap().1));
                        }
                    };

                    // TODO: make calc readable
                    if l2_range_to_submit.is_none()
                        || (l2_range_to_submit.unwrap().1 .0 - l2_range_to_submit.unwrap().0 .0 + 1)
                            < self.params.min_soft_confirmations_per_commitment
                    {
                        warn!(
                            "Sequencer: not enough soft confirmations to submit commitment: {:?}. L1 heights: {:?}",
                            l2_range_to_submit,
                            _l1_height_range
                        );
                    } else {
                        warn!("Sequencer: enough soft confirmations to submit commitment");
                        let l2_range_to_submit = l2_range_to_submit.unwrap();

                        // calculate exclusive range end
                        let range_end = BatchNumber(l2_range_to_submit.1 .0 + 1); // cannnot add u64 to BatchNumber directly

                        let soft_confirmation_hashes = self
                            .ledger_db
                            .get_soft_batch_range(&(l2_range_to_submit.0..range_end))
                            .expect("Sequencer: Failed to get soft batch range")
                            .iter()
                            .map(|sb| sb.hash)
                            .collect::<Vec<[u8; 32]>>();

                        // sanity check
                        assert_eq!(
                            soft_confirmation_hashes.len(),
                            (l2_range_to_submit.1 .0 - l2_range_to_submit.0 .0 + 1) as usize
                        );

                        // build merkle tree over soft confirmations

                        let merkle_root = MerkleTree::<Sha256>::from_leaves(
                            soft_confirmation_hashes.clone().as_slice(),
                        )
                        .root();

                        warn!(
                            "Sequencer: submitting commitment, L1 heights: {:?}, L2 heights: {:?}, merkle root: {:?}, soft confirmations: {:?}",
                            _l1_height_range, l2_range_to_submit, merkle_root, soft_confirmation_hashes
                        );

                        // submit commitment
                        self.da_service
                            .send_transaction(
                                (
                                    merkle_root.unwrap(),
                                    l2_range_to_submit.0,
                                    l2_range_to_submit.1,
                                )
                                    .try_to_vec()
                                    .unwrap()
                                    .as_slice(),
                            )
                            .await
                            .expect("Sequencer: Failed to send commitment");

                        for i in _l1_height_range.unwrap().0..=_l1_height_range.unwrap().1 {
                            self.ledger_db
                                .set_last_sequencer_commitment_l1_height(SlotNumber(i))
                                .expect(
                                    "Sequencer: Failed to set last sequencer commitment L1 height",
                                );
                        }
                    }

                    // TODO: this is where we would include forced transactions from the new L1 block
                }

                let unsigned_batch = UnsignedSoftConfirmationBatch {
                    da_slot_height: last_finalized_block.header().height(),
                    txs: vec![signed_blob.clone()],
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

                let signed_soft_batch = self.sign_soft_confirmation_batch(unsigned_batch);

                // TODO: handle error
                self.rollup.runner.process(signed_soft_batch).await?;

                // get last block remove only txs in block

                self.mempool
                    .remove_transactions(self.db_provider.last_block_tx_hashes());

                // not really a good way to get the last soft batch number :)
                let last_soft_batch_number = self
                    .ledger_db
                    .get_head_soft_batch()
                    .expect("Sequencer: Failed to get head soft batch")
                    .unwrap()
                    .0; // cannot be None here

                // connect L1 and L2 height
                self.ledger_db
                    .connect_l1_l2_heights(
                        SlotNumber(last_finalized_block.header().height()),
                        last_soft_batch_number,
                    )
                    .expect("Sequencer: Failed to set L1 L2 connection");
            }
        }
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(&mut self, raw_message: Vec<u8>) -> Vec<u8> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let accounts = Accounts::<C>::default();
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());
        let nonce = match accounts
            .get_account(self.sov_tx_signer_priv_key.pub_key(), &mut working_set)
            .expect("Sequencer: Failed to get sov-account")
        {
            AccountExists { addr: _, nonce } => nonce,
            AccountEmpty => 0,
        };

        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        Transaction::<C>::new_signed_tx(&self.sov_tx_signer_priv_key, raw_message, 0, 0, 0, nonce)
            .try_to_vec()
            .unwrap()
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
