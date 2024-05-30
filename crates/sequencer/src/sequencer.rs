use std::cmp::Ordering;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::anyhow;
use borsh::ser::BorshSerialize;
use citrea_evm::{CallMessage, Evm, RlpEvmTransaction};
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use jsonrpsee::RpcModule;
use reth_primitives::{FromRecoveredPooledTransaction, IntoRecoveredTransaction};
use reth_provider::BlockReaderIdExt;
use reth_transaction_pool::{
    BestTransactionsAttributes, EthPooledTransaction, PoolTransaction, ValidPoolTransaction,
};
use shared_backup_db::{CommitmentStatus, PostgresConnector};
use soft_confirmation_rule_enforcer::SoftConfirmationRuleEnforcer;
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
use sov_rollup_interface::services::da::{BlobWithNotifier, DaService};
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitVariant, RollupPublicKeys, RpcConfig};
use tokio::sync::oneshot::channel as oneshot_channel;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

use crate::commitment_controller;
use crate::config::SequencerConfig;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::rpc::{create_rpc_module, RpcContext};
use crate::utils::recover_raw_transaction;

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
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    storage_manager: Sm,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    sequencer_pub_key: Vec<u8>,
    rpc_config: RpcConfig,
    soft_confirmation_rule_enforcer: SoftConfirmationRuleEnforcer<C, Da::Spec>,
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
        storage: C::Storage,
        config: SequencerConfig,
        stf: Stf,
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        public_keys: RollupPublicKeys,
        ledger_db: LedgerDB,
        rpc_config: RpcConfig,
    ) -> anyhow::Result<Self> {
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

        let pool = CitreaMempool::new(db_provider.clone(), config.mempool_conf.clone())?;

        let deposit_mempool = Arc::new(Mutex::new(DepositDataMempool::new()));

        let sov_tx_signer_priv_key =
            C::PrivateKey::try_from(&hex::decode(&config.private_key).unwrap()).unwrap();

        let soft_confirmation_rule_enforcer =
            SoftConfirmationRuleEnforcer::<C, <Da as DaService>::Spec>::default();

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
            sequencer_pub_key: public_keys.sequencer_public_key,
            rpc_config,
            soft_confirmation_rule_enforcer,
        })
    }

    pub async fn start_rpc_server(
        &self,
        channel: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
        methods: RpcModule<()>,
    ) -> anyhow::Result<()> {
        let methods = self.register_rpc_methods(methods).await?;

        let listen_address = SocketAddr::new(
            self.rpc_config
                .bind_host
                .parse()
                .map_err(|e| anyhow!("Failed to parse bind host: {}", e))?,
            self.rpc_config.bind_port,
        );

        let max_connections = self.rpc_config.max_connections;

        let _handle = tokio::spawn(async move {
            let server = jsonrpsee::server::ServerBuilder::default()
                .max_connections(max_connections)
                .build([listen_address].as_ref())
                .await;

            match server {
                Ok(server) => {
                    let bound_address = match server.local_addr() {
                        Ok(address) => address,
                        Err(e) => {
                            error!("{}", e);
                            return;
                        }
                    };
                    if let Some(channel) = channel {
                        if let Err(e) = channel.send(bound_address) {
                            error!("Could not send bound_address {}: {}", bound_address, e);
                            return;
                        }
                    }
                    info!("Starting RPC server at {} ", &bound_address);

                    let _server_handle = server.start(methods);
                    futures::future::pending::<()>().await;
                }
                Err(e) => {
                    error!("Could not start RPC server: {}", e);
                }
            }
        });
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err, ret)]
    async fn produce_l2_block(
        &mut self,
        da_block: <Da as DaService>::FilteredBlock,
        l1_fee_rate: u128,
        l2_block_mode: L2BlockMode,
        pg_pool: &Option<PostgresConnector>,
    ) -> anyhow::Result<()> {
        let da_height = da_block.header().height();
        let (l2_height, l1_height) = match self
            .ledger_db
            .get_head_soft_batch()
            .map_err(|e| anyhow!("Failed to get head soft batch: {}", e))?
        {
            Some((l2_height, sb)) => (l2_height.0 + 1, sb.da_slot_height),
            None => (0, da_height),
        };
        anyhow::ensure!(
            l1_height == da_height || l1_height + 1 == da_height,
            "Sequencer: L1 height mismatch, expected {da_height} (or {da_height}-1), got {l1_height}",
        );

        let timestamp = chrono::Local::now().timestamp() as u64;
        let pub_key = self
            .sov_tx_signer_priv_key
            .pub_key()
            .try_to_vec()
            .map_err(Into::<anyhow::Error>::into)?;

        let deposit_data = self
            .deposit_mempool
            .lock()
            .await
            .fetch_deposits(self.config.deposit_mempool_fetch_limit);

        let batch_info = HookSoftConfirmationInfo {
            da_slot_height: da_block.header().height(),
            da_slot_hash: da_block.header().hash().into(),
            da_slot_txs_commitment: da_block.header().txs_commitment().into(),
            pre_state_root: self.state_root.clone().as_ref().to_vec(),
            deposit_data: deposit_data.clone(),
            pub_key,
            l1_fee_rate,
            timestamp,
        };
        let mut signed_batch: SignedSoftConfirmationBatch = batch_info.clone().into();
        // initially create sc info and call begin soft confirmation hook with it

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .map_err(Into::<anyhow::Error>::into)?;
        info!(
            "Applying soft batch on DA block: {}",
            hex::encode(da_block.header().hash().into())
        );

        let pub_key = signed_batch.pub_key().clone();

        let block_gas_limit = self.db_provider.cfg().block_gas_limit;

        // We iterate through the mempool to select a bunch of transactions which are
        // within the block's gas limit. The actual gas consumption for transactions is taken
        // into account instead of the gas limit specified by the transaction to prevent
        // transactions from reserving the whole block's gas limit.
        let mut selected_transactions = vec![];
        let mut prev_cumulative_gas_used: u64 = 0;
        loop {
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
                    // Since we have multiple iterations, we only want to account for
                    // system transactions once in the block's gas limit.
                    let cumulative_gas_used = if selected_transactions.is_empty() {
                        self.db_provider
                            .evm
                            .get_pending_txs_cumulative_gas_used(&mut batch_workspace)
                    } else {
                        0
                    };

                    let new_transactions_batch = match l2_block_mode {
                        L2BlockMode::Empty => vec![],
                        L2BlockMode::NotEmpty => self.get_best_transactions(cumulative_gas_used)?,
                    };
                    selected_transactions.extend(new_transactions_batch);

                    let rlp_txs: Vec<RlpEvmTransaction> = selected_transactions
                        .iter()
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
                        <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(
                            call_txs,
                        );
                    let signed_blob = self.make_blob(raw_message)?;
                    let txs = vec![signed_blob.clone()];

                    let (mut batch_workspace, tx_receipts) =
                        self.stf.apply_soft_batch_txs(txs.clone(), batch_workspace);

                    // create the unsigned batch with the txs then sign th sc
                    let unsigned_batch = UnsignedSoftConfirmationBatch::new(
                        da_block.header().height(),
                        da_block.header().hash().into(),
                        da_block.header().txs_commitment().into(),
                        self.state_root.clone().as_ref().to_vec(),
                        txs,
                        deposit_data.clone(),
                        l1_fee_rate,
                        timestamp,
                    );

                    let mut signed_soft_batch =
                        self.sign_soft_confirmation_batch(unsigned_batch)?;

                    let evm = Evm::<C>::default();
                    let applied_transactions = evm.get_pending_transactions(&mut batch_workspace);

                    // Remove the transactions from the mempool after having applied them.
                    self.mempool.remove_transactions(
                        applied_transactions.iter().map(|tx| tx.hash()).collect(),
                    );

                    // Check if we have more transactions we can fit into this block.
                    let cumulative_gas_used = applied_transactions
                        .iter()
                        .fold(0u64, |acc, tx| acc + tx.gas_used());
                    // Keep filing transactions until we fill at least half the block with transactions.
                    if cumulative_gas_used > prev_cumulative_gas_used
                        && (cumulative_gas_used as f64) < (block_gas_limit as f64 * 0.5)
                    {
                        prev_cumulative_gas_used = cumulative_gas_used;
                        continue;
                    }

                    // After applying transactions, remove them from the mempool.
                    // This is to select a new list of transactions to fill the whole block.

                    let (batch_receipt, checkpoint) = self.stf.end_soft_batch(
                        self.sequencer_pub_key.as_ref(),
                        &mut signed_soft_batch,
                        tx_receipts,
                        batch_workspace,
                    );

                    // nasty hack to access state
                    let mut intermediary_working_set = checkpoint.to_revertable();

                    // before finalize we can get tx hashes that failed due to L1 fees.
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
                        deposit_data,
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

                    let mut txs_to_remove = self.db_provider.last_block_tx_hashes()?;
                    txs_to_remove.extend(l1_fee_failed_txs);

                    self.mempool.remove_transactions(txs_to_remove.clone());

                    if let Some(pg_pool) = pg_pool.clone() {
                        // TODO: Is this okay? I'm not sure because we have a loop in this and I can't do async in spawn_blocking
                        tokio::spawn(async move {
                            let txs = txs_to_remove
                                .iter()
                                .map(|tx_hash| tx_hash.to_vec())
                                .collect::<Vec<Vec<u8>>>();
                            if let Err(e) = pg_pool.delete_txs_by_tx_hashes(txs).await {
                                warn!("Failed to remove txs from mempool: {:?}", e);
                            }
                        });
                    }
                    // connect L1 and L2 height
                    self.ledger_db.extend_l2_range_of_l1_slot(
                        SlotNumber(da_block.header().height()),
                        BatchNumber(l2_height),
                    )?;
                }
                (Err(err), batch_workspace) => {
                    warn!(
                        "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                        err
                    );
                    batch_workspace.revert();
                    return Err(anyhow!(
                        "Failed to apply begin soft confirmation hook: {:?}",
                        err
                    ));
                }
            }

            break;
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err, ret)]
    pub async fn build_block(
        &mut self,
        pg_pool: &Option<PostgresConnector>,
        da_height_tx: UnboundedSender<u64>,
    ) -> anyhow::Result<()> {
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
                    .map_err(|e| anyhow!(e))?
                    .height(),
            );
        }

        let prev_l1_height = prev_l1_height.expect("Should be set at this point");

        debug!("Sequencer: prev L1 height: {:?}", prev_l1_height);

        let last_finalized_height = self
            .da_service
            .get_last_finalized_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();

        debug!(
            "Sequencer: last finalized height: {:?}",
            last_finalized_height
        );

        let fee_rate_range = self.get_l1_fee_rate_range()?;

        let l1_fee_rate = self
            .da_service
            .get_fee_rate()
            .await
            .map_err(|e| anyhow!(e))?;

        let l1_fee_rate = l1_fee_rate.clamp(*fee_rate_range.start(), *fee_rate_range.end());

        let last_commitable_l1_height = match last_finalized_height.cmp(&prev_l1_height) {
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
                        let da_block = self
                            .da_service
                            .get_block_at(skipped_height)
                            .await
                            .map_err(|e| anyhow!(e))?;
                        // pool does not need to be passed here as no tx is included
                        self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::Empty, &None)
                            .await?;
                    }
                }
                let last_commitable_l1_height = last_finalized_height - 1;
                Some(last_commitable_l1_height)
            }
        };

        if let Some(last_commitable_l1_height) = last_commitable_l1_height {
            da_height_tx
                .unbounded_send(last_commitable_l1_height)
                .expect("Commitment thread is dead");
            // TODO: this is where we would include forced transactions from the new L1 block
        }

        let last_finalized_block = self
            .da_service
            .get_block_at(last_finalized_height)
            .await
            .map_err(|e| anyhow!(e))?;

        self.produce_l2_block(
            last_finalized_block,
            l1_fee_rate,
            L2BlockMode::NotEmpty,
            pg_pool,
        )
        .await?;
        Ok(())
    }

    fn spawn_commitment_thread(&self) -> UnboundedSender<u64> {
        let (da_height_tx, mut da_height_rx) = unbounded::<u64>();
        let ledger_db = self.ledger_db.clone();
        let inscription_queue = self.da_service.get_send_transaction_queue();
        let min_soft_confirmations_per_commitment =
            self.config.min_soft_confirmations_per_commitment;
        let db_config = self.config.db_config.clone();
        tokio::spawn(async move {
            while let Some(prev_l1_height) = da_height_rx.next().await {
                debug!("Sequencer: new L1 block, checking if commitment should be submitted");

                let commitment_info = commitment_controller::get_commitment_info(
                    &ledger_db,
                    min_soft_confirmations_per_commitment,
                    prev_l1_height,
                )
                .unwrap(); // TODO unwrap()

                if let Some(commitment_info) = commitment_info {
                    debug!("Sequencer: enough soft confirmations to submit commitment");
                    let l2_range_to_submit = commitment_info.l2_height_range.clone();

                    // calculate exclusive range end
                    let range_end = BatchNumber(l2_range_to_submit.end().0 + 1); // cannnot add u64 to BatchNumber directly

                    let soft_confirmation_hashes = ledger_db
                        .get_soft_batch_range(&(*l2_range_to_submit.start()..range_end))
                        .unwrap() // TODO unwrap
                        .iter()
                        .map(|sb| sb.hash)
                        .collect::<Vec<[u8; 32]>>();

                    let commitment = commitment_controller::get_commitment(
                        commitment_info.clone(),
                        soft_confirmation_hashes,
                    )
                    .unwrap(); // TODO unwrap

                    info!("Sequencer: submitting commitment: {:?}", commitment);

                    let blob = DaData::SequencerCommitment(commitment.clone())
                        .try_to_vec()
                        .map_err(|e| anyhow!(e))
                        .unwrap(); // TODO unwrap
                    let (notify, rx) = oneshot_channel();
                    let request = BlobWithNotifier { blob, notify };
                    inscription_queue
                        .send(request)
                        .expect("Bitcoin service already stopped");
                    let tx_id = rx
                        .await
                        .expect("DA service is dead")
                        .expect("send_transaction cannot fail");

                    ledger_db
                        .set_last_sequencer_commitment_l1_height(SlotNumber(
                            commitment_info.l1_height_range.end().0,
                        ))
                        .expect("Sequencer: Failed to set last sequencer commitment L1 height");

                    warn!("Commitment info: {:?}", commitment_info);
                    let l1_start_height = commitment_info.l1_height_range.start().0;
                    let l1_end_height = commitment_info.l1_height_range.end().0;
                    let l2_start = l2_range_to_submit.start().0 as u32;
                    let l2_end = l2_range_to_submit.end().0 as u32;
                    if let Some(db_config) = db_config.clone() {
                        match PostgresConnector::new(db_config).await {
                            Ok(pg_connector) => {
                                pg_connector
                                    .insert_sequencer_commitment(
                                        l1_start_height as u32,
                                        l1_end_height as u32,
                                        Into::<[u8; 32]>::into(tx_id).to_vec(),
                                        commitment.l1_start_block_hash.to_vec(),
                                        commitment.l1_end_block_hash.to_vec(),
                                        l2_start,
                                        l2_end,
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
            }
        });
        da_height_tx
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // TODO: hotfix for mock da
        self.da_service
            .get_block_at(1)
            .await
            .map_err(|e| anyhow!(e))?;

        let da_height_tx = self.spawn_commitment_thread();

        // If connected to offchain db first check if the commitments are in sync
        let mut pg_pool = None;
        if let Some(db_config) = self.config.db_config.clone() {
            pg_pool = match PostgresConnector::new(db_config).await {
                Ok(pg_connector) => {
                    match self.compare_commitments_from_db(pg_connector.clone()).await {
                        Ok(()) => info!("Sequencer: Commitments are in sync"),
                        Err(e) => {
                            warn!("Sequencer: Offchain db error: {:?}", e);
                        }
                    }
                    match self.restore_mempool(pg_connector.clone()).await {
                        Ok(()) => info!("Sequencer: Mempool restored"),
                        Err(e) => {
                            warn!("Sequencer: Mempool restore error: {:?}", e);
                        }
                    }
                    Some(pg_connector)
                }
                Err(e) => {
                    warn!("Failed to connect to postgres: {:?}", e);
                    None
                }
            };
        }

        // If sequencer is in test mode, it will build a block every time it receives a message
        if self.config.test_mode {
            loop {
                if (self.l2_force_block_rx.next().await).is_some() {
                    if let Err(e) = self.build_block(&pg_pool, da_height_tx.clone()).await {
                        error!("Sequencer error: {}", e);
                    }
                }
            }
        }
        // If sequencer is in production mode, it will build a block every 2 seconds
        else {
            loop {
                sleep(Duration::from_secs(2)).await;
                if let Err(e) = self.build_block(&pg_pool, da_height_tx.clone()).await {
                    error!("Sequencer error: {}", e);
                }
            }
        }
    }

    fn get_best_transactions(
        &self,
        cumulative_gas_used: u64,
    ) -> anyhow::Result<Vec<Arc<ValidPoolTransaction<EthPooledTransaction>>>> {
        let cfg = self.db_provider.cfg();
        let latest_header = self
            .db_provider
            .latest_header()
            .map_err(|e| anyhow!("Failed to get latest header: {}", e))?
            .ok_or(anyhow!("Latest header must always exist"))?
            .unseal();

        let base_fee = latest_header
            .next_block_base_fee(cfg.base_fee_params)
            .ok_or(anyhow!("Failed to get next block base fee"))?;

        let best_txs_with_base_fee = self
            .mempool
            .best_transactions_with_attributes(BestTransactionsAttributes::base_fee(base_fee));
        // TODO: implement block builder instead of just including every transaction in order
        let mut cumulative_gas_used = cumulative_gas_used;

        Ok(best_txs_with_base_fee
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
            .collect())
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(&mut self, raw_message: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce()?;

        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        Transaction::<C>::new_signed_tx(&self.sov_tx_signer_priv_key, raw_message, 0, nonce)
            .try_to_vec()
            .map_err(|e| anyhow!(e))
    }

    /// Signs necessary info and returns a BlockTemplate
    fn sign_soft_confirmation_batch(
        &mut self,
        soft_confirmation: UnsignedSoftConfirmationBatch,
    ) -> anyhow::Result<SignedSoftConfirmationBatch> {
        let raw = soft_confirmation.try_to_vec().map_err(|e| anyhow!(e))?;

        let hash = <C as sov_modules_api::Spec>::Hasher::digest(raw.as_slice()).into();

        let signature = self.sov_tx_signer_priv_key.sign(&raw);

        Ok(SignedSoftConfirmationBatch::new(
            hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.pre_state_root(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.txs(),
            soft_confirmation.deposit_data(),
            signature.try_to_vec().map_err(|e| anyhow!(e))?,
            self.sov_tx_signer_priv_key
                .pub_key()
                .try_to_vec()
                .map_err(|e| anyhow!(e))?,
            soft_confirmation.timestamp(),
        ))
    }

    /// Fetches nonce from state
    fn get_nonce(&self) -> anyhow::Result<u64> {
        let accounts = Accounts::<C>::default();
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());

        match accounts
            .get_account(self.sov_tx_signer_priv_key.pub_key(), &mut working_set)
            .map_err(|e| anyhow!("Sequencer: Failed to get sov-account: {}", e))?
        {
            AccountExists { addr: _, nonce } => Ok(nonce),
            AccountEmpty => Ok(0),
        }
    }

    /// Creates a shared RpcContext with all required data.
    async fn create_rpc_context(&self) -> RpcContext<C> {
        let l2_force_block_tx = self.l2_force_block_tx.clone();
        let mut pg_pool = None;
        if let Some(pg_config) = self.config.db_config.clone() {
            pg_pool = match PostgresConnector::new(pg_config).await {
                Ok(pg_connector) => Some(Arc::new(pg_connector)),
                Err(e) => {
                    warn!("Failed to connect to postgres: {:?}", e);
                    None
                }
            };
        }
        RpcContext {
            mempool: self.mempool.clone(),
            deposit_mempool: self.deposit_mempool.clone(),
            l2_force_block_tx,
            storage: self.storage.clone(),
            test_mode: self.config.test_mode,
            pg_pool,
        }
    }

    /// Updates the given RpcModule with Sequencer methods.
    pub async fn register_rpc_methods(
        &self,
        mut rpc_methods: jsonrpsee::RpcModule<()>,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::Error> {
        let rpc_context = self.create_rpc_context().await;
        let rpc = create_rpc_module(rpc_context)?;
        rpc_methods.merge(rpc)?;
        Ok(rpc_methods)
    }

    pub async fn restore_mempool(
        &self,
        pg_connector: PostgresConnector,
    ) -> Result<(), anyhow::Error> {
        let mempool_txs = pg_connector.get_all_txs().await?;
        for tx in mempool_txs {
            let recovered =
                recover_raw_transaction(reth_primitives::Bytes::from(tx.tx.as_slice().to_vec()))
                    .unwrap();
            let pooled_tx = EthPooledTransaction::from_recovered_pooled_transaction(recovered);

            let _ = self.mempool.add_external_transaction(pooled_tx).await?;
        }
        Ok(())
    }

    pub async fn compare_commitments_from_db(
        &self,
        pg_connector: PostgresConnector,
    ) -> Result<(), anyhow::Error> {
        let ledger_commitment_l1_height =
            self.ledger_db.get_last_sequencer_commitment_l1_height()?;

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

    fn get_l1_fee_rate_range(&self) -> Result<RangeInclusive<u128>, anyhow::Error> {
        let mut working_set = WorkingSet::<C>::new(self.storage.clone());

        self.soft_confirmation_rule_enforcer
            .get_next_min_max_l1_fee_rate(&mut working_set)
            .map_err(|e| anyhow::anyhow!("Error reading min max l1 fee rate: {}", e))
    }
}
