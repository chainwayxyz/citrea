use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec;

use borsh::ser::BorshSerialize;
use citrea_evm::{CallMessage, RlpEvmTransaction};
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use jsonrpsee::RpcModule;
use reth_primitives::IntoRecoveredTransaction;
use reth_provider::BlockReaderIdExt;
use reth_transaction_pool::{BestTransactionsAttributes, TransactionPool};
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    Context, EncodeCall, PrivateKey, SignedSoftConfirmationBatch, SlotData,
    UnsignedSoftConfirmationBatch, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaSpec};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitVariant, RunnerConfig};
use tracing::{debug, info, warn};

use crate::commitment_controller;
use crate::config::SequencerConfig;
use crate::db_provider::DbProvider;
use crate::mempool::{create_mempool, CitreaMempool};
use crate::rpc::{create_rpc_module, RpcContext};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;

pub struct CitreaSequencer<C, Da, Sm, Vm, Stf>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
{
    da_service: Da,
    mempool: Arc<CitreaMempool<C>>,
    sov_tx_signer_priv_key: C::PrivateKey,
    l2_force_block_tx: UnboundedSender<()>,
    l2_force_block_rx: UnboundedReceiver<()>,
    db_provider: DbProvider<C>,
    storage: C::Storage,
    ledger_db: LedgerDB,
    config: SequencerConfig,
    stf: Stf,
    storage_manager: Sm,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    sequencer_pub_key: Vec<u8>,
    listen_address: SocketAddr,
}

impl<C, Da, Sm, Vm, Stf> CitreaSequencer<C, Da, Sm, Vm, Stf>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<
            Vm,
            Da::Spec,
            Condition = <Da::Spec as DaSpec>::ValidityCondition,
            PreState = Sm::NativeStorage,
            ChangeSet = Sm::NativeChangeSet,
        > + StfBlueprintTrait<C, Da::Spec, Vm>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        da_service: Da,
        sov_tx_signer_priv_key: C::PrivateKey,
        storage: C::Storage,
        config: SequencerConfig,
        stf: Stf,
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        sequencer_pub_key: Vec<u8>,
        ledger_db: LedgerDB,
        runner_config: RunnerConfig,
    ) -> Result<Self, anyhow::Error> {
        let (l2_force_block_tx, l2_force_block_rx) = unbounded();

        let prev_state_root = match init_variant {
            InitVariant::Initialized(state_root) => {
                debug!("Chain is already initialized. Skipping initialization.");
                state_root
            }
            InitVariant::Genesis {
                block_header,
                genesis_params: params,
            } => {
                info!(
                    "No history detected. Initializing chain on block_header={:?}...",
                    block_header
                );
                let storage = storage_manager.create_storage_on_l2_height(0)?;
                let (genesis_root, initialized_storage) = stf.init_chain(storage, params);
                storage_manager.save_change_set_l2(0, initialized_storage)?;
                storage_manager.finalize_l2(0)?;
                info!(
                    "Chain initialization is done. Genesis root: 0x{}",
                    hex::encode(genesis_root.as_ref()),
                );
                genesis_root
            }
        };

        // used as client of reth's mempool
        let db_provider = DbProvider::new(storage.clone());

        let pool = create_mempool(db_provider.clone());

        let rpc_config = runner_config.rpc_config;

        let listen_address = SocketAddr::new(rpc_config.bind_host.parse()?, rpc_config.bind_port);

        Ok(Self {
            da_service,
            mempool: Arc::new(pool),
            sov_tx_signer_priv_key,
            l2_force_block_tx,
            l2_force_block_rx,
            db_provider,
            storage,
            ledger_db,
            config,
            stf,
            storage_manager,
            state_root: prev_state_root,
            sequencer_pub_key,
            listen_address,
        })
    }

    pub async fn start_rpc_server(
        &self,
        channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
        methods: RpcModule<()>,
    ) -> Result<(), anyhow::Error> {
        let methods = self.register_rpc_methods(methods)?;

        let listen_address = self.listen_address;
        let _handle = tokio::spawn(async move {
            let server = jsonrpsee::server::ServerBuilder::default()
                .build([listen_address].as_ref())
                .await
                .unwrap();

            let bound_address = server.local_addr().unwrap();
            if let Some(channel) = channel {
                channel.send(bound_address).unwrap();
            }
            info!("Starting RPC server at {} ", &bound_address);

            let _server_handle = server.start(methods);
            futures::future::pending::<()>().await;
        });
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // TODO: hotfix for mock da
        self.da_service.get_block_at(1).await.unwrap();

        loop {
            if (self.l2_force_block_rx.next().await).is_some() {
                // best txs with base fee
                // get base fee from last blocks => header => next base fee() function
                let cfg: citrea_evm::EvmChainConfig = self.db_provider.cfg();

                let base_fee = self
                    .db_provider
                    .latest_header()
                    .expect("Failed to get latest header")
                    .map(|header| header.unseal().next_block_base_fee(cfg.base_fee_params))
                    .expect("Failed to get next block base fee")
                    .unwrap();

                let best_txs_with_base_fee = self.mempool.best_transactions_with_attributes(
                    BestTransactionsAttributes::base_fee(base_fee),
                );

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

                debug!(
                    "Sequencer: publishing block with {} transactions",
                    rlp_txs.len()
                );

                let call_txs = CallMessage { txs: rlp_txs };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(call_txs);
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

                debug!("Sequencer: prev L1 height: {:?}", prev_l1_height);

                let last_finalized_height = self
                    .da_service
                    .get_last_finalized_block_header()
                    .await
                    .unwrap()
                    .height();

                debug!(
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

                    // Compare if there is no skip
                    if last_finalized_block.header().prev_hash()
                        != previous_l1_block.header().hash()
                    {
                        // TODO: This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                    }
                    debug!("Sequencer: new L1 block, checking if commitment should be submitted");

                    let commitment_info = commitment_controller::get_commitment_info(
                        &self.ledger_db,
                        self.config.min_soft_confirmations_per_commitment,
                        prev_l1_height,
                    );

                    if commitment_info.is_some() {
                        debug!("Sequencer: enough soft confirmations to submit commitment");
                        let commitment_info = commitment_info.unwrap();
                        let l2_range_to_submit = commitment_info.l2_height_range.clone();

                        // calculate exclusive range end
                        let range_end = BatchNumber(l2_range_to_submit.end().0 + 1); // cannnot add u64 to BatchNumber directly

                        let soft_confirmation_hashes = self
                            .ledger_db
                            .get_soft_batch_range(&(*l2_range_to_submit.start()..range_end))
                            .expect("Sequencer: Failed to get soft batch range")
                            .iter()
                            .map(|sb| sb.hash)
                            .collect::<Vec<[u8; 32]>>();

                        let commitment = commitment_controller::get_commitment(
                            commitment_info.clone(),
                            soft_confirmation_hashes,
                        );

                        info!("Sequencer: submitting commitment: {:?}", commitment);

                        // submit commitment
                        self.da_service
                            .send_transaction(
                                DaData::SequencerCommitment(commitment)
                                    .try_to_vec()
                                    .unwrap()
                                    .as_slice(),
                            )
                            .await
                            .expect("Sequencer: Failed to send commitment");

                        self.ledger_db
                            .set_last_sequencer_commitment_l1_height(SlotNumber(
                                commitment_info.l1_height_range.end().0,
                            ))
                            .expect("Sequencer: Failed to set last sequencer commitment L1 height");
                    }

                    // TODO: this is where we would include forced transactions from the new L1 block
                }

                let batch_info = HookSoftConfirmationInfo {
                    da_slot_height: last_finalized_block.header().height(),
                    da_slot_hash: last_finalized_block.header().hash().into(),
                    pre_state_root: self.state_root.clone().as_ref().to_vec(),
                    pub_key: self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
                    l1_fee_rate,
                };
                let mut signed_batch: SignedSoftConfirmationBatch = batch_info.clone().into();
                // initially create sc info and call begin soft confirmation hook with it
                let txs = vec![signed_blob.clone()];

                let l2_height = match self
                    .ledger_db
                    .get_head_soft_batch()
                    .expect("Sequencer: Failed to get head soft batch")
                {
                    Some((l2_height, _)) => l2_height.0 + 1,
                    None => 0,
                };
                let last_finalized_block = self
                    .da_service
                    .get_block_at(last_finalized_block.header().height())
                    .await
                    .unwrap();
                let prestate = self
                    .storage_manager
                    .create_storage_on_l2_height(l2_height)
                    .unwrap();

                info!(
                    "Applying soft batch on DA block: {}",
                    hex::encode(last_finalized_block.header().hash().into())
                );

                let pub_key = signed_batch.pub_key().clone();

                match self.stf.begin_soft_batch(
                    &pub_key,
                    &self.state_root,
                    prestate.clone(),
                    Default::default(),
                    last_finalized_block.header(),
                    &mut signed_batch,
                ) {
                    (Ok(()), batch_workspace) => {
                        let (batch_workspace, tx_receipts) =
                            self.stf.apply_soft_batch_txs(txs.clone(), batch_workspace);

                        // create the unsigned batch with the txs then sign th sc
                        let unsigned_batch = UnsignedSoftConfirmationBatch::new(
                            last_finalized_block.header().height(),
                            last_finalized_block.header().hash().into(),
                            self.state_root.clone().as_ref().to_vec(),
                            txs,
                            l1_fee_rate,
                        );

                        let mut signed_soft_batch =
                            self.sign_soft_confirmation_batch(unsigned_batch);

                        let (batch_receipt, checkpoint) = self.stf.end_soft_batch(
                            self.sequencer_pub_key.as_ref(),
                            &mut signed_soft_batch,
                            tx_receipts,
                            batch_workspace,
                        );

                        // Finalize soft confirmation
                        let slot_result = self.stf.finalize_soft_batch(
                            batch_receipt,
                            checkpoint,
                            prestate,
                            &mut signed_soft_batch,
                        );

                        if slot_result.state_root.as_ref() == self.state_root.as_ref() {
                            debug!("Limiting number is reached for the current L1 block. State root is the same as before, skipping");
                            // TODO: Check if below is legit
                            self.storage_manager
                                .save_change_set_l2(l2_height, slot_result.change_set)?;

                            tracing::debug!("Finalizing l2 height: {:?}", l2_height);
                            self.storage_manager.finalize_l2(l2_height)?;
                            return Ok(());
                        }

                        info!(
                            "State root after applying slot: {:?}",
                            slot_result.state_root
                        );

                        let mut data_to_commit = SlotCommit::new(last_finalized_block.clone());
                        for receipt in slot_result.batch_receipts {
                            data_to_commit.add_batch(receipt);
                        }

                        // TODO: This will be a single receipt once we have apply_soft_batch.
                        let batch_receipt = data_to_commit.batch_receipts()[0].clone();

                        let next_state_root = slot_result.state_root;

                        let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
                            pre_state_root: self.state_root.as_ref().to_vec(),
                            post_state_root: next_state_root.as_ref().to_vec(),
                            phantom_data: PhantomData::<u64>,
                            batch_hash: batch_receipt.batch_hash,
                            da_slot_hash: last_finalized_block.header().hash(),
                            da_slot_height: last_finalized_block.header().height(),
                            tx_receipts: batch_receipt.tx_receipts,
                            soft_confirmation_signature: signed_soft_batch.signature().to_vec(),
                            pub_key: signed_soft_batch.pub_key().to_vec(),
                            l1_fee_rate: signed_soft_batch.l1_fee_rate(),
                        };

                        // TODO: this will only work for mock da
                        // when https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218
                        // is merged, rpc will access up to date storage then we won't need to finalize rigth away.
                        // however we need much better DA + finalization logic here
                        self.storage_manager
                            .save_change_set_l2(l2_height, slot_result.change_set)?;

                        tracing::debug!("Finalizing l2 height: {:?}", l2_height);
                        self.storage_manager.finalize_l2(l2_height)?;

                        self.state_root = next_state_root;

                        self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;

                        self.mempool
                            .remove_transactions(self.db_provider.last_block_tx_hashes());

                        // connect L1 and L2 height
                        self.ledger_db
                            .extend_l2_range_of_l1_slot(
                                SlotNumber(last_finalized_block.header().height()),
                                BatchNumber(l2_height),
                            )
                            .expect("Sequencer: Failed to set L1 L2 connection");
                    }
                    (Err(err), batch_workspace) => {
                        warn!("Failed to apply soft confirmation hook: {:?} \n reverting batch workspace", err);
                        batch_workspace.revert();
                    }
                }
            }
        }
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(&mut self, raw_message: Vec<u8>) -> Vec<u8> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce();

        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        Transaction::<C>::new_signed_tx(&self.sov_tx_signer_priv_key, raw_message, 0, nonce)
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

        SignedSoftConfirmationBatch::new(
            hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.pre_state_root(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.txs(),
            signature.try_to_vec().unwrap(),
            self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
        )
    }

    /// Fetches nonce from state
    fn get_nonce(&self) -> u64 {
        let accounts = Accounts::<C>::default();
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());

        match accounts
            .get_account(self.sov_tx_signer_priv_key.pub_key(), &mut working_set)
            .expect("Sequencer: Failed to get sov-account")
        {
            AccountExists { addr: _, nonce } => nonce,
            AccountEmpty => 0,
        }
    }

    /// Creates a shared RpcContext with all required data.
    fn create_rpc_context(&self) -> RpcContext<C> {
        let l2_force_block_tx = self.l2_force_block_tx.clone();
        RpcContext {
            mempool: self.mempool.clone(),
            l2_force_block_tx,
            storage: self.storage.clone(),
        }
    }

    /// Updates the given RpcModule with Sequencer methods.
    pub fn register_rpc_methods(
        &self,
        mut rpc_methods: jsonrpsee::RpcModule<()>,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::Error> {
        let rpc_context = self.create_rpc_context();
        let rpc = create_rpc_module(rpc_context)?;
        rpc_methods.merge(rpc).unwrap();
        Ok(rpc_methods)
    }
}
