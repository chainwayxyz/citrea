use std::cmp::Ordering;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use borsh::ser::BorshSerialize;
use citrea_evm::{CallMessage, Evm, RlpEvmTransaction};
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use jsonrpsee::RpcModule;
use reth_primitives::IntoRecoveredTransaction;
use reth_provider::BlockReaderIdExt;
use reth_transaction_pool::{BestTransactionsAttributes, PoolTransaction};
use shared_backup_db::{CommitmentStatus, PostgresConnector, SharedBackupDbConfig};
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
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitVariant, RpcConfig, RunnerConfig};
use tokio::sync::oneshot::Receiver as OneshotReceiver;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::commitment_controller::{self, CommitmentInfo};
use crate::config::SequencerConfig;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
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
    deposit_mempool: DepositDataMempool,
    storage_manager: Sm,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    sequencer_pub_key: Vec<u8>,
    rpc_config: RpcConfig,
}

enum L2BlockMode {
    Empty,
    NotEmpty,
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
            InitVariant::Genesis(params) => {
                info!("No history detected. Initializing chain...",);
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

        let pool = CitreaMempool::new(db_provider.clone(), config.mempool_conf.clone());

        let deposit_mempool = DepositDataMempool::new();

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
            deposit_mempool,
            storage_manager,
            state_root: prev_state_root,
            sequencer_pub_key,
            rpc_config: runner_config.rpc_config,
        })
    }

    pub async fn start_rpc_server(
        &self,
        channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
        methods: RpcModule<()>,
    ) -> Result<(), anyhow::Error> {
        let methods = self.register_rpc_methods(methods)?;

        let listen_address = SocketAddr::new(
            self.rpc_config
                .bind_host
                .parse()
                .expect("Failed to parse bind host"),
            self.rpc_config.bind_port,
        );

        let max_connections = self.rpc_config.max_connections;

        let _handle = tokio::spawn(async move {
            let server = jsonrpsee::server::ServerBuilder::default()
                .max_connections(max_connections)
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

    async fn produce_l2_block(
        &mut self,
        da_block: <Da as DaService>::FilteredBlock,
        l1_fee_rate: u64,
        l2_block_mode: L2BlockMode,
    ) -> Result<(), anyhow::Error> {
        let da_height = da_block.header().height();
        let (l2_height, l1_height) = match self
            .ledger_db
            .get_head_soft_batch()
            .expect("Sequencer: Failed to get head soft batch")
        {
            Some((l2_height, sb)) => (l2_height.0 + 1, sb.da_slot_height),
            None => (0, da_height),
        };
        anyhow::ensure!(
            l1_height == da_height || l1_height + 1 == da_height,
            "Sequencer: L1 height mismatch, expected {da_height} (or {da_height}-1), got {l1_height}",
        );

        let timestamp = chrono::Local::now().timestamp() as u64;

        let deposit_data = self
            .deposit_mempool
            .fetch_deposits(self.config.deposit_mempool_fetch_limit);

        let batch_info = HookSoftConfirmationInfo {
            da_slot_height: da_block.header().height(),
            da_slot_hash: da_block.header().hash().into(),
            da_slot_txs_commitment: da_block.header().txs_commitment().into(),
            pre_state_root: self.state_root.clone().as_ref().to_vec(),
            pub_key: self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
            deposit_data,
            l1_fee_rate,
            timestamp,
        };
        let mut signed_batch: SignedSoftConfirmationBatch = batch_info.clone().into();
        // initially create sc info and call begin soft confirmation hook with it

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .unwrap();

        info!(
            "Applying soft batch on DA block: {}",
            hex::encode(da_block.header().hash().into())
        );

        let pub_key = signed_batch.pub_key().clone();

        match self.stf.begin_soft_batch(
            &pub_key,
            &self.state_root,
            prestate.clone(),
            Default::default(),
            da_block.header(),
            &mut signed_batch,
        ) {
            (Ok(()), mut batch_workspace) => {
                // if there's going to be system txs somewhere other than the beginning of the block
                // TODO: Handle system txs gas usage in the middle and end of the block
                let system_tx_gas_usage = self
                    .db_provider
                    .evm
                    .get_pending_txs_cumulative_gas_used(&mut batch_workspace);

                let rlp_txs = match l2_block_mode {
                    L2BlockMode::Empty => vec![],
                    L2BlockMode::NotEmpty => self.get_best_transactions(system_tx_gas_usage),
                };
                debug!(
                    "Sequencer: publishing block with {} transactions",
                    rlp_txs.len()
                );
                let call_txs = CallMessage { txs: rlp_txs };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(call_txs);
                let signed_blob = self.make_blob(raw_message);
                let txs = vec![signed_blob.clone()];

                let (batch_workspace, tx_receipts) =
                    self.stf.apply_soft_batch_txs(txs.clone(), batch_workspace);

                // create the unsigned batch with the txs then sign th sc
                let unsigned_batch = UnsignedSoftConfirmationBatch::new(
                    da_block.header().height(),
                    da_block.header().hash().into(),
                    da_block.header().txs_commitment().into(),
                    self.state_root.clone().as_ref().to_vec(),
                    txs,
                    vec![],
                    l1_fee_rate,
                    timestamp,
                );

                let mut signed_soft_batch = self.sign_soft_confirmation_batch(unsigned_batch);

                let (batch_receipt, checkpoint) = self.stf.end_soft_batch(
                    self.sequencer_pub_key.as_ref(),
                    &mut signed_soft_batch,
                    tx_receipts,
                    batch_workspace,
                );

                // before finalize we can get tx hashes that failed due to L1 fees.
                let evm = Evm::<C>::default();

                // nasty hack to access state
                let mut intermediary_working_set = checkpoint.to_revertable();

                let l1_fee_failed_txs =
                    evm.get_l1_fee_failed_txs(&mut intermediary_working_set.accessory_state());

                let checkpoint = intermediary_working_set.checkpoint();

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

                let mut data_to_commit = SlotCommit::new(da_block.clone());
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
                    da_slot_hash: da_block.header().hash(),
                    da_slot_height: da_block.header().height(),
                    da_slot_txs_commitment: da_block.header().txs_commitment(),
                    tx_receipts: batch_receipt.tx_receipts,
                    soft_confirmation_signature: signed_soft_batch.signature().to_vec(),
                    pub_key: signed_soft_batch.pub_key().to_vec(),
                    deposit_data: vec![],
                    l1_fee_rate: signed_soft_batch.l1_fee_rate(),
                    timestamp: signed_soft_batch.timestamp(),
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

                let mut txs_to_remove = self.db_provider.last_block_tx_hashes();
                txs_to_remove.extend(l1_fee_failed_txs);

                self.mempool.remove_transactions(txs_to_remove);

                // connect L1 and L2 height
                self.ledger_db
                    .extend_l2_range_of_l1_slot(
                        SlotNumber(da_block.header().height()),
                        BatchNumber(l2_height),
                    )
                    .expect("Sequencer: Failed to set L1 L2 connection");
            }
            (Err(err), batch_workspace) => {
                warn!(
                    "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
                batch_workspace.revert();
            }
        }
        Ok(())
    }

    pub async fn build_block(&mut self) -> Result<(), anyhow::Error> {
        // best txs with base fee
        // get base fee from last blocks => header => next base fee() function

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

        let l1_fee_rate = self.da_service.get_fee_rate().await.unwrap();

        let new_da_block = match last_finalized_height.cmp(&prev_l1_height) {
            Ordering::Less => {
                panic!("DA L1 height is less than Ledger finalized height");
            }
            Ordering::Equal => None,
            Ordering::Greater => {
                // Compare if there is no skip
                if last_finalized_height - prev_l1_height > 1 {
                    // This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                    for skipped_height in (prev_l1_height + 1)..last_finalized_height {
                        debug!(
                            "Sequencer: publishing empty L2 for skipped L1 block: {:?}",
                            skipped_height
                        );
                        let da_block = self.da_service.get_block_at(skipped_height).await.unwrap();
                        self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::Empty)
                            .await?;
                    }
                }
                let prev_l1_height = last_finalized_height - 1;
                Some(prev_l1_height)
            }
        };

        if let Some(prev_l1_height) = new_da_block {
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
                let tx_id = self
                    .da_service
                    .send_tx_no_wait(
                        DaData::SequencerCommitment(commitment.clone())
                            .try_to_vec()
                            .unwrap(),
                    )
                    .await;

                let l1_start_height = commitment_info.l1_height_range.start().0;
                let l1_end_height = commitment_info.l1_height_range.end().0;

                // this function will save the commitment to the offchain db if db config is some
                // and will also update the last sequencer commitment L1 height if the l1 tx is successful
                self.await_commitment_tx_and_store(
                    tx_id,
                    self.config.db_config.clone(),
                    l1_start_height,
                    l1_end_height,
                    commitment,
                    l2_range_to_submit.clone(),
                    commitment_info.clone(),
                )
                .await;
            }

            // TODO: this is where we would include forced transactions from the new L1 block
        }

        let last_finalized_block = self
            .da_service
            .get_block_at(last_finalized_height)
            .await
            .unwrap();

        self.produce_l2_block(last_finalized_block, l1_fee_rate, L2BlockMode::NotEmpty)
            .await?;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // TODO: hotfix for mock da
        self.da_service.get_block_at(1).await.unwrap();

        // If connected to offchain db first check if the commitments are in sync
        if let Some(db_config) = self.config.db_config.clone() {
            match self.compare_commitments_from_db(db_config).await {
                Ok(()) => info!("Sequencer: Commitments are in sync"),
                Err(e) => {
                    warn!("Sequencer: Offchain db error: {:?}", e);
                }
            }
        }

        // If sequencer is in test mode, it will build a block every time it receives a message
        if self.config.test_mode {
            loop {
                if (self.l2_force_block_rx.next().await).is_some() {
                    self.build_block().await?;
                }
            }
        }
        // If sequencer is in production mode, it will build a block every 2 seconds
        else {
            loop {
                sleep(Duration::from_secs(2)).await;
                self.build_block().await?;
            }
        }
    }

    fn get_best_transactions(&self, system_tx_gas_usage: u64) -> Vec<RlpEvmTransaction> {
        let cfg = self.db_provider.cfg();
        let latest_header = self
            .db_provider
            .latest_header()
            .expect("Failed to get latest header")
            .expect("Latest header must always exist")
            .unseal();

        let base_fee = latest_header
            .next_block_base_fee(cfg.base_fee_params)
            .expect("Failed to get next block base fee");

        let best_txs_with_base_fee = self
            .mempool
            .best_transactions_with_attributes(BestTransactionsAttributes::base_fee(base_fee));
        // TODO: implement block builder instead of just including every transaction in order
        let mut cumulative_gas_used = 0;

        // Add the system tx gas usage to the cumulative gas used
        cumulative_gas_used += system_tx_gas_usage;

        best_txs_with_base_fee
            .into_iter()
            .filter(|tx| {
                // Don't include transactions that exceed the block gas limit
                let tx_gas_limit = tx.transaction.gas_limit();
                let fits_into_block = cumulative_gas_used + tx_gas_limit <= cfg.block_gas_limit;
                if fits_into_block {
                    cumulative_gas_used += tx_gas_limit
                }
                fits_into_block
            })
            .map(|tx| {
                tx.to_recovered_transaction()
                    .into_signed()
                    .envelope_encoded()
                    .to_vec()
            })
            .map(|rlp| RlpEvmTransaction { rlp })
            .collect::<Vec<RlpEvmTransaction>>()
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
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.pre_state_root(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.txs(),
            soft_confirmation.deposit_data(),
            signature.try_to_vec().unwrap(),
            self.sov_tx_signer_priv_key.pub_key().try_to_vec().unwrap(),
            soft_confirmation.timestamp(),
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
            deposit_mempool: Arc::new(Mutex::new(self.deposit_mempool.clone())),
            l2_force_block_tx,
            storage: self.storage.clone(),
            test_mode: self.config.test_mode,
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

    #[allow(clippy::too_many_arguments)]
    pub async fn await_commitment_tx_and_store(
        &self,
        tx_id: OneshotReceiver<Result<<Da as DaService>::TransactionId, <Da as DaService>::Error>>,
        db_config: Option<SharedBackupDbConfig>,
        l1_start_height: u64,
        l1_end_height: u64,
        commitment: SequencerCommitment,
        l2_range: RangeInclusive<BatchNumber>,
        commitment_info: CommitmentInfo,
    ) {
        // spawn an async task in the background and await the tx_id then save to pg
        let ledger_db = self.ledger_db.clone();
        tokio::spawn(async move {
            match tx_id.await {
                Ok(Ok(tx_id)) => {
                    ledger_db
                        .set_last_sequencer_commitment_l1_height(SlotNumber(
                            commitment_info.l1_height_range.end().0,
                        ))
                        .expect("Sequencer: Failed to set last sequencer commitment L1 height");
                    warn!("Commitment info: {:?}", commitment_info);
                    if let Some(db_config) = db_config {
                        match PostgresConnector::new(db_config).await {
                            Ok(pg_connector) => {
                                pg_connector
                                    .insert_sequencer_commitment(
                                        l1_start_height as u32,
                                        l1_end_height as u32,
                                        tx_id.into().to_vec(),
                                        commitment.l1_start_block_hash.to_vec(),
                                        commitment.l1_end_block_hash.to_vec(),
                                        l2_range.start().0 as u32,
                                        (l2_range.end().0 + 1) as u32,
                                        commitment.merkle_root.to_vec(),
                                        CommitmentStatus::Mempool,
                                    )
                                    .await
                                    .expect("Sequencer: Failed to insert sequencer commitment");
                            }
                            Err(e) => {
                                warn!("Failed to connect to postgres: {:?}", e);
                            }
                        }
                    }
                }
                _ => {
                    warn!("Sequencer: Failed to submit commitment: ");
                }
            }
        });
    }

    pub async fn compare_commitments_from_db(
        &self,
        db_config: SharedBackupDbConfig,
    ) -> Result<(), anyhow::Error> {
        let ledger_commitment_l1_height =
            self.ledger_db.get_last_sequencer_commitment_l1_height()?;

        match PostgresConnector::new(db_config).await {
            Ok(pg_connector) => {
                let commitment = pg_connector.get_last_commitment().await?;
                // check if last commitment in db matches sequencer's last commitment
                match commitment {
                    Some(db_commitment) => {
                        // this means that the last commitment in the db is not the same as the sequencer's last commitment
                        if db_commitment.l1_end_height as u64
                            > ledger_commitment_l1_height.unwrap_or(SlotNumber(0)).0
                        {
                            self.ledger_db
                                .set_last_sequencer_commitment_l1_height(SlotNumber(
                                    db_commitment.l1_end_height as u64,
                                ))?
                        }
                        Ok(())
                    }
                    None => Ok(()),
                }
            }
            Err(e) => {
                warn!("Failed to connect to postgres: {:?}", e);
                Err(anyhow::anyhow!("Failed to connect to postgres: {:?}", e))
            }
        }
    }
}
