use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::anyhow;
use borsh::BorshDeserialize;
use citrea_evm::{CallMessage, Evm, RlpEvmTransaction, MIN_TRANSACTION_GAS};
use citrea_primitives::types::SoftConfirmationHash;
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use hyper::Method;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use reth_primitives::{Address, FromRecoveredPooledTransaction, IntoRecoveredTransaction, TxHash};
use reth_provider::{AccountReader, BlockReaderIdExt};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, ChangedAccount, EthPooledTransaction,
    ValidPoolTransaction,
};
use shared_backup_db::{CommitmentStatus, PostgresConnector};
use soft_confirmation_rule_enforcer::SoftConfirmationRuleEnforcer;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::{SequencerLedgerOps, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    BlobReaderTrait, Context, EncodeCall, PrivateKey, SignedSoftConfirmationBatch, SlotData,
    StateDiff, UnsignedSoftConfirmationBatch, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaSpec, SequencerCommitment};
use sov_rollup_interface::services::da::{BlobWithNotifier, DaService};
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitVariant, RollupPublicKeys, RpcConfig};
use tokio::sync::oneshot::channel as oneshot_channel;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::{sleep, Instant};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::commitment_controller;
use crate::config::SequencerConfig;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::rpc::{create_rpc_module, RpcContext};
use crate::utils::recover_raw_transaction;

const MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD: u64 = 300 * 1024;

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
/// Represents information about the current DA state.
///
/// Contains previous height, latest finalized block and fee rate.
type L1Data<Da> = (<Da as DaService>::FilteredBlock, u128);

pub struct CitreaSequencer<C, Da, Sm, Vm, Stf, DB>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    da_service: Arc<Da>,
    mempool: Arc<CitreaMempool<C>>,
    sov_tx_signer_priv_key: C::PrivateKey,
    l2_force_block_tx: UnboundedSender<()>,
    l2_force_block_rx: UnboundedReceiver<()>,
    db_provider: DbProvider<C>,
    storage: C::Storage,
    ledger_db: DB,
    config: SequencerConfig,
    stf: Stf,
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    storage_manager: Sm,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    batch_hash: SoftConfirmationHash,
    sequencer_pub_key: Vec<u8>,
    rpc_config: RpcConfig,
    soft_confirmation_rule_enforcer: SoftConfirmationRuleEnforcer<C, Da::Spec>,
    last_state_diff: StateDiff,
    soft_confirmation_tx: broadcast::Sender<u64>,
}

enum L2BlockMode {
    Empty,
    NotEmpty,
}

impl<C, Da, Sm, Vm, Stf, DB> CitreaSequencer<C, Da, Sm, Vm, Stf, DB>
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
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        da_service: Arc<Da>,
        storage: C::Storage,
        config: SequencerConfig,
        stf: Stf,
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        public_keys: RollupPublicKeys,
        ledger_db: DB,
        rpc_config: RpcConfig,
        soft_confirmation_tx: broadcast::Sender<u64>,
    ) -> anyhow::Result<Self> {
        let (l2_force_block_tx, l2_force_block_rx) = unbounded();

        let (prev_state_root, prev_batch_hash) = match init_variant {
            InitVariant::Initialized((state_root, batch_hash)) => {
                debug!("Chain is already initialized. Skipping initialization.");
                (state_root, batch_hash)
            }
            InitVariant::Genesis(params) => {
                info!("No history detected. Initializing chain...",);
                let storage = storage_manager.create_storage_on_l2_height(0)?;
                let (genesis_root, initialized_storage) = stf.init_chain(storage, params);
                storage_manager.save_change_set_l2(0, initialized_storage)?;
                storage_manager.finalize_l2(0)?;
                ledger_db.set_l2_genesis_state_root(&genesis_root)?;
                info!(
                    "Chain initialization is done. Genesis root: 0x{}",
                    hex::encode(genesis_root.as_ref()),
                );
                (genesis_root, [0; 32])
            }
        };

        // used as client of reth's mempool
        let db_provider = DbProvider::new(storage.clone());

        let pool = CitreaMempool::new(db_provider.clone(), config.mempool_conf.clone())?;

        let deposit_mempool = Arc::new(Mutex::new(DepositDataMempool::new()));

        let sov_tx_signer_priv_key = C::PrivateKey::try_from(&hex::decode(&config.private_key)?)?;

        let soft_confirmation_rule_enforcer =
            SoftConfirmationRuleEnforcer::<C, <Da as DaService>::Spec>::default();

        // Initialize the sequencer with the last state diff from DB.
        let last_state_diff = ledger_db.get_state_diff()?;

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
            batch_hash: prev_batch_hash,
            sequencer_pub_key: public_keys.sequencer_public_key,
            rpc_config,
            soft_confirmation_rule_enforcer,
            last_state_diff,
            soft_confirmation_tx,
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
        let max_subscriptions_per_connection = self.rpc_config.max_subscriptions_per_connection;
        let max_request_body_size = self.rpc_config.max_request_body_size;
        let max_response_body_size = self.rpc_config.max_response_body_size;
        let batch_requests_limit = self.rpc_config.batch_requests_limit;

        let cors = CorsLayer::new()
            .allow_methods([Method::POST, Method::OPTIONS])
            .allow_origin(Any)
            .allow_headers(Any);
        let middleware = tower::ServiceBuilder::new().layer(cors);

        let _handle = tokio::spawn(async move {
            let server = ServerBuilder::default()
                .max_connections(max_connections)
                .max_subscriptions_per_connection(max_subscriptions_per_connection)
                .max_request_body_size(max_request_body_size)
                .max_response_body_size(max_response_body_size)
                .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
                .set_http_middleware(middleware)
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

    #[allow(clippy::too_many_arguments)]
    async fn dry_run_transactions(
        &mut self,
        transactions: Box<
            dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>,
        >,
        pub_key: &[u8],
        prestate: <Sm as HierarchicalStorageManager<<Da as DaService>::Spec>>::NativeStorage,
        da_block_header: <<Da as DaService>::Spec as DaSpec>::BlockHeader,
        mut signed_batch: SignedSoftConfirmationBatch,
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        match self.stf.begin_soft_batch(
            pub_key,
            &self.state_root,
            prestate.clone(),
            Default::default(),
            &da_block_header,
            &mut signed_batch,
        ) {
            (Ok(()), mut working_set_to_discard) => {
                let block_gas_limit = self.db_provider.cfg().block_gas_limit;

                let evm = Evm::<C>::default();

                match l2_block_mode {
                    L2BlockMode::NotEmpty => {
                        let mut all_txs = vec![];

                        for evm_tx in transactions {
                            let rlp_tx = RlpEvmTransaction {
                                rlp: evm_tx
                                    .to_recovered_transaction()
                                    .into_signed()
                                    .envelope_encoded()
                                    .to_vec(),
                            };

                            let call_txs = CallMessage {
                                txs: vec![rlp_tx.clone()],
                            };
                            let raw_message = <Runtime<C, Da::Spec> as EncodeCall<
                                citrea_evm::Evm<C>,
                            >>::encode_call(call_txs);
                            let signed_blob =
                                self.make_blob(raw_message, &mut working_set_to_discard)?;

                            let txs = vec![signed_blob.clone()];

                            let (batch_workspace, _) = self
                                .stf
                                .apply_soft_batch_txs(txs.clone(), working_set_to_discard);

                            working_set_to_discard = batch_workspace;

                            let last_tx =
                                evm.get_last_pending_transaction(&mut working_set_to_discard);

                            if let Some(last_tx) = last_tx {
                                if last_tx.hash() == *evm_tx.hash() {
                                    all_txs.push(rlp_tx);
                                }

                                if last_tx.cumulative_gas_used()
                                    >= block_gas_limit - MIN_TRANSACTION_GAS
                                {
                                    break;
                                }
                            }
                        }

                        // before finalize we can get tx hashes that failed due to L1 fees.
                        // nasty hack to access state
                        let l1_fee_failed_txs = evm
                            .get_l1_fee_failed_txs(&mut working_set_to_discard.accessory_state());

                        Ok((all_txs, l1_fee_failed_txs))
                    }
                    L2BlockMode::Empty => Ok((vec![], vec![])),
                }
            }
            (Err(err), batch_workspace) => {
                warn!(
                    "DryRun: Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
                batch_workspace.revert();
                Err(anyhow!(
                    "DryRun: Failed to apply begin soft confirmation hook: {:?}",
                    err
                ))
            }
        }
    }

    async fn produce_l2_block(
        &mut self,
        da_block: <Da as DaService>::FilteredBlock,
        l1_fee_rate: u128,
        l2_block_mode: L2BlockMode,
        pg_pool: &Option<PostgresConnector>,
        last_used_l1_height: u64,
    ) -> anyhow::Result<(u64, bool)> {
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
        let pub_key = borsh::to_vec(&self.sov_tx_signer_priv_key.pub_key())
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
        // initially create sc info and call begin soft confirmation hook with it
        let mut signed_batch: SignedSoftConfirmationBatch = batch_info.clone().into();

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .map_err(Into::<anyhow::Error>::into)?;
        debug!(
            "Applying soft batch on DA block: {}",
            hex::encode(da_block.header().hash().into())
        );

        let pub_key = signed_batch.pub_key().clone();

        let evm_txs = self.get_best_transactions()?;

        // Dry running transactions would basically allow for figuring out a list of
        // all transactions that would fit into the current block and the list of transactions
        // which do not have enough balance to pay for the L1 fee.
        let (txs_to_run, l1_fee_failed_txs) = self
            .dry_run_transactions(
                evm_txs,
                &pub_key,
                prestate.clone(),
                da_block.header().clone(),
                signed_batch.clone(),
                l2_block_mode,
            )
            .await?;

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .map_err(Into::<anyhow::Error>::into)?;

        // Execute the selected transactions
        match self.stf.begin_soft_batch(
            &pub_key,
            &self.state_root,
            prestate.clone(),
            Default::default(),
            da_block.header(),
            &mut signed_batch,
        ) {
            (Ok(()), mut batch_workspace) => {
                let evm_txs_count = txs_to_run.len();
                let call_txs = CallMessage { txs: txs_to_run };
                let raw_message =
                    <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(call_txs);
                let signed_blob = self.make_blob(raw_message, &mut batch_workspace)?;
                let txs = vec![signed_blob.clone()];

                let (batch_workspace, tx_receipts) =
                    self.stf.apply_soft_batch_txs(txs.clone(), batch_workspace);

                // create the unsigned batch with the txs then sign th sc
                let unsigned_batch = UnsignedSoftConfirmationBatch::new(
                    da_block.header().height(),
                    da_block.header().hash().into(),
                    da_block.header().txs_commitment().into(),
                    txs,
                    deposit_data.clone(),
                    l1_fee_rate,
                    timestamp,
                );

                let mut signed_soft_batch =
                    self.sign_soft_confirmation_batch(unsigned_batch, self.batch_hash)?;

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
                    debug!("Max L2 blocks per L1 is reached for the current L1 block. State root is the same as before, skipping");
                    // TODO: Check if below is legit
                    self.storage_manager
                        .save_change_set_l2(l2_height, slot_result.change_set)?;

                    tracing::debug!("Finalizing l2 height: {:?}", l2_height);
                    self.storage_manager.finalize_l2(l2_height)?;
                    return Ok((last_used_l1_height, false));
                }

                trace!(
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
                    state_root: next_state_root.as_ref().to_vec(),
                    phantom_data: PhantomData::<u64>,
                    hash: signed_soft_batch.hash(),
                    prev_hash: signed_soft_batch.prev_hash(),
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

                self.storage_manager
                    .save_change_set_l2(l2_height, slot_result.change_set)?;

                // TODO: this will only work for mock da
                // when https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218
                // is merged, rpc will access up to date storage then we won't need to finalize rigth away.
                // however we need much better DA + finalization logic here
                self.storage_manager.finalize_l2(l2_height)?;

                self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;

                // connect L1 and L2 height
                self.ledger_db.extend_l2_range_of_l1_slot(
                    SlotNumber(da_block.header().height()),
                    BatchNumber(l2_height),
                )?;

                // Only errors when there are no receivers
                let _ = self.soft_confirmation_tx.send(l2_height);

                let l1_height = da_block.header().height();
                info!(
                    "New block #{}, DA #{}, Tx count: #{}",
                    l2_height, l1_height, evm_txs_count,
                );

                self.state_root = next_state_root;
                self.batch_hash = signed_soft_batch.hash();

                let mut txs_to_remove = self.db_provider.last_block_tx_hashes()?;
                txs_to_remove.extend(l1_fee_failed_txs);

                self.mempool.remove_transactions(txs_to_remove.clone());

                let account_updates = self.get_account_updates()?;

                self.mempool.update_accounts(account_updates);

                let merged_state_diff = self.merge_state_diffs(
                    self.last_state_diff.clone(),
                    slot_result.state_diff.clone(),
                );
                // Serialize the state diff to check size later.
                let serialized_state_diff = bincode::serialize(&merged_state_diff)?;
                let state_diff_threshold_reached =
                    serialized_state_diff.len() as u64 > MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD;
                if state_diff_threshold_reached {
                    self.last_state_diff.clone_from(&slot_result.state_diff);
                    self.ledger_db
                        .set_state_diff(self.last_state_diff.clone())?;
                } else {
                    // Store state diff.
                    self.last_state_diff = merged_state_diff;
                    self.ledger_db
                        .set_state_diff(self.last_state_diff.clone())?;
                }

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

                Ok((da_block.header().height(), state_diff_threshold_reached))
            }
            (Err(err), batch_workspace) => {
                warn!(
                    "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
                batch_workspace.revert();
                Err(anyhow!(
                    "Failed to apply begin soft confirmation hook: {:?}",
                    err
                ))
            }
        }
    }

    async fn try_submit_commitment(
        &mut self,
        state_diff_threshold_reached: bool,
    ) -> anyhow::Result<()> {
        debug!("Sequencer: Checking if commitment should be submitted");

        let commitment_info = commitment_controller::get_commitment_info(
            &self.ledger_db,
            self.config.min_soft_confirmations_per_commitment,
            state_diff_threshold_reached,
        )?;
        if let Some(commitment_info) = commitment_info {
            self.submit_commitment(commitment_info, false).await?;
        }
        Ok(())
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn resubmit_pending_commitments(&mut self) -> anyhow::Result<()> {
        info!("Resubmitting pending commitments");

        let pending_db_commitments = self.ledger_db.get_pending_commitments_l2_range()?;
        debug!("Pending db commitments: {:?}", pending_db_commitments);

        let pending_mempool_commitments = self.get_pending_mempool_commitments().await;
        debug!(
            "Commitments that are already in DA mempool: {:?}",
            pending_mempool_commitments
        );

        let last_commitment_l1_height = self
            .ledger_db
            .get_l1_height_of_last_commitment()?
            .unwrap_or(SlotNumber(1));
        let mined_commitments = self
            .get_mined_commitments_from(last_commitment_l1_height)
            .await?;
        debug!(
            "Commitments that are already mined by DA: {:?}",
            mined_commitments
        );

        let mut pending_commitments_to_remove = vec![];
        pending_commitments_to_remove.extend(pending_mempool_commitments);
        pending_commitments_to_remove.extend(mined_commitments);

        // TODO: also take mined DA blocks into account
        for (l2_start, l2_end) in pending_db_commitments {
            if pending_commitments_to_remove.iter().any(|commitment| {
                commitment.l2_start_block_number == l2_start.0
                    && commitment.l2_end_block_number == l2_end.0
            }) {
                // Update last sequencer commitment l2 height
                match self.ledger_db.get_last_sequencer_commitment_l2_height()? {
                    Some(last_commitment_l2_height) if last_commitment_l2_height >= l2_end => {}
                    _ => {
                        self.ledger_db
                            .set_last_sequencer_commitment_l2_height(l2_end)?;
                    }
                };

                // Delete from pending db if it is already in DA mempool
                self.ledger_db
                    .delete_pending_commitment_l2_range(&(l2_start, l2_end))?;
            } else {
                // Submit commitment
                let commitment_info = commitment_controller::CommitmentInfo {
                    l2_height_range: l2_start..=l2_end,
                };
                self.submit_commitment(commitment_info, true).await?;
            }
        }

        Ok(())
    }

    async fn submit_commitment(
        &mut self,
        commitment_info: commitment_controller::CommitmentInfo,
        wait_for_da_response: bool,
    ) -> anyhow::Result<()> {
        let l2_start = *commitment_info.l2_height_range.start();
        let l2_end = *commitment_info.l2_height_range.end();

        // Clear state diff early
        self.ledger_db.set_state_diff(vec![])?;
        self.last_state_diff = vec![];

        // calculate exclusive range end
        let range_end = BatchNumber(l2_end.0 + 1); // cannnot add u64 to BatchNumber directly

        let soft_confirmation_hashes = self
            .ledger_db
            .get_soft_batch_range(&(l2_start..range_end))?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        let commitment =
            commitment_controller::get_commitment(commitment_info, soft_confirmation_hashes)?;

        debug!("Sequencer: submitting commitment: {:?}", commitment);

        let blob = borsh::to_vec(&DaData::SequencerCommitment(commitment.clone()))
            .map_err(|e| anyhow!(e))?;
        let (notify, rx) = oneshot_channel();
        let request = BlobWithNotifier { blob, notify };
        self.da_service
            .get_send_transaction_queue()
            .send(request)
            .map_err(|_| anyhow!("Bitcoin service already stopped!"))?;

        info!(
            "Sent commitment to DA queue. L2 range: #{}-{}",
            l2_start.0, l2_end.0,
        );

        let ledger_db = self.ledger_db.clone();
        let db_config = self.config.db_config.clone();
        let handle_da_response = async move {
            let result: anyhow::Result<()> = async move {
                let tx_id = rx
                    .await
                    .map_err(|_| anyhow!("DA service is dead!"))?
                    .map_err(|_| anyhow!("Send transaction cannot fail"))?;

                ledger_db
                    .set_last_sequencer_commitment_l2_height(l2_end)
                    .map_err(|_| {
                        anyhow!("Sequencer: Failed to set last sequencer commitment L2 height")
                    })?;

                if let Some(db_config) = db_config {
                    match PostgresConnector::new(db_config).await {
                        Ok(pg_connector) => {
                            pg_connector
                                .insert_sequencer_commitment(
                                    Into::<[u8; 32]>::into(tx_id).to_vec(),
                                    l2_start.0 as u32,
                                    l2_end.0 as u32,
                                    commitment.merkle_root.to_vec(),
                                    CommitmentStatus::Mempool,
                                )
                                .await
                                .map_err(|_| {
                                    anyhow!("Sequencer: Failed to insert sequencer commitment")
                                })?;
                        }
                        Err(e) => {
                            warn!("Failed to connect to postgres: {:?}", e);
                        }
                    }
                }

                ledger_db.delete_pending_commitment_l2_range(&(l2_start, l2_end))?;

                info!("New commitment. L2 range: #{}-{}", l2_start.0, l2_end.0);
                Ok(())
            }
            .await;

            if let Err(err) = result {
                error!(
                    "Error in spawned task for handling commitment result: {}",
                    err
                );
            }
        };

        if wait_for_da_response {
            // Handle DA response blocking
            handle_da_response.await;
        } else {
            // Add commitment to pending commitments
            self.ledger_db
                .put_pending_commitment_l2_range(&(l2_start, l2_end))?;

            // Handle DA response non-blocking
            tokio::spawn(handle_da_response);
        }
        Ok(())
    }

    async fn get_pending_mempool_commitments(&self) -> Vec<SequencerCommitment> {
        self.da_service
            .get_relevant_blobs_of_pending_transactions()
            .await
            .into_iter()
            .filter_map(|mut blob| match DaData::try_from_slice(blob.full_data()) {
                Ok(da_data) => match da_data {
                    DaData::SequencerCommitment(commitment) => Some(commitment),
                    _ => None,
                },
                Err(err) => {
                    warn!("Pending transaction blob failed to be parsed: {}", err);
                    None
                }
            })
            .collect()
    }

    async fn get_mined_commitments_from(
        &self,
        da_height: SlotNumber,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let head_da_height = self
            .da_service
            .get_head_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();
        let mut mined_commitments = vec![];
        for height in da_height.0..=head_da_height {
            let block = self
                .da_service
                .get_block_at(height)
                .await
                .map_err(|e| anyhow!(e))?;
            let blobs = self.da_service.extract_relevant_blobs(&block);
            let iter = blobs.into_iter().filter_map(|mut blob| {
                match DaData::try_from_slice(blob.full_data()) {
                    Ok(da_data) => match da_data {
                        DaData::SequencerCommitment(commitment) => Some(commitment),
                        _ => None,
                    },
                    Err(err) => {
                        warn!("Pending transaction blob failed to be parsed: {}", err);
                        None
                    }
                }
            });
            mined_commitments.extend(iter);
        }

        Ok(mined_commitments)
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // Resubmit if there were pending commitments on restart
        self.resubmit_pending_commitments().await?;

        // TODO: hotfix for mock da
        self.da_service
            .get_block_at(1)
            .await
            .map_err(|e| anyhow!(e))?;

        // If connected to offchain db first check if the commitments are in sync
        let mut pg_pool = None;
        if let Some(db_config) = self.config.db_config.clone() {
            pg_pool = match PostgresConnector::new(db_config).await {
                Ok(pg_connector) => {
                    match self.sync_commitments_from_db(pg_connector.clone()).await {
                        Ok(()) => debug!("Sequencer: Commitments are in sync"),
                        Err(e) => {
                            warn!("Sequencer: Offchain db error: {:?}", e);
                        }
                    }
                    match self.restore_mempool(pg_connector.clone()).await {
                        Ok(()) => debug!("Sequencer: Mempool restored"),
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

        // Initialize our knowledge of the state of the DA-layer
        let fee_rate_range = get_l1_fee_rate_range::<C, Da>(
            self.storage.clone(),
            self.soft_confirmation_rule_enforcer.clone(),
        )?;
        let (mut last_finalized_block, l1_fee_rate) =
            match get_da_block_data(self.da_service.clone()).await {
                Ok(l1_data) => l1_data,
                Err(e) => {
                    error!("{}", e);
                    return Err(e);
                }
            };
        let mut l1_fee_rate = l1_fee_rate.clamp(*fee_rate_range.start(), *fee_rate_range.end());
        let mut last_finalized_height = last_finalized_block.header().height();

        let mut last_used_l1_height = match self.ledger_db.get_head_soft_batch() {
            Ok(Some((_, sb))) => sb.da_slot_height,
            Ok(None) => last_finalized_height, // starting for the first time
            Err(e) => {
                return Err(anyhow!("previous L1 height: {}", e));
            }
        };

        debug!("Sequencer: Last used L1 height: {:?}", last_used_l1_height);

        // Setup required workers to update our knowledge of the DA layer every X seconds (configurable).
        let (da_height_update_tx, mut da_height_update_rx) = mpsc::channel(1);
        let (da_commitment_tx, mut da_commitment_rx) = unbounded::<bool>();
        let da_monitor = da_block_monitor(
            self.da_service.clone(),
            da_height_update_tx,
            self.config.da_update_interval_ms,
        );
        tokio::pin!(da_monitor);

        let target_block_time = Duration::from_millis(self.config.block_production_interval_ms);
        let mut parent_block_exec_time = Duration::from_secs(0);

        // In case the sequencer falls behind on DA blocks, we need to produce at least 1
        // empty block per DA block. Which means that we have to keep count of missed blocks
        // and only resume normal operations once the sequencer has caught up.
        let mut missed_da_blocks_count = 0;

        loop {
            let mut interval = tokio::time::interval(target_block_time - parent_block_exec_time);
            // The first ticket completes immediately.
            // See: https://docs.rs/tokio/latest/tokio/time/struct.Interval.html#method.tick
            interval.tick().await;

            tokio::select! {
                // Run the DA monitor worker
                _ = &mut da_monitor => {},
                // Receive updates from DA layer worker.
                l1_data = da_height_update_rx.recv() => {
                    // Stop receiving updates from DA layer until we have caught up.
                    if missed_da_blocks_count > 0 {
                        continue;
                    }
                    if let Some(l1_data) = l1_data {
                        (last_finalized_block, l1_fee_rate) = l1_data;
                        last_finalized_height = last_finalized_block.header().height();

                        if last_finalized_block.header().height() > last_used_l1_height {
                            let skipped_blocks = last_finalized_height - last_used_l1_height - 1;
                            if skipped_blocks > 0 {
                                // This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
                                warn!(
                                    "Sequencer is falling behind on L1 blocks by {:?} blocks",
                                    skipped_blocks
                                );

                                // Missed DA blocks means that we produce n - 1 empty blocks, 1 per missed DA block.
                                missed_da_blocks_count = skipped_blocks;
                            }
                        }
                    }
                },
                commitment_threshold_reached = da_commitment_rx.select_next_some() => {
                    if let Err(e) = self.try_submit_commitment(commitment_threshold_reached).await {
                        error!("Failed to submit commitment: {}", e);
                    }
                },
                // If sequencer is in test mode, it will build a block every time it receives a message
                // The RPC from which the sender can be called is only registered for test mode. This means
                // that evey though we check the receiver here, it'll never be "ready" to be consumed unless in test mode.
                _ = self.l2_force_block_rx.next(), if self.config.test_mode => {
                    if missed_da_blocks_count > 0 {
                        debug!("We have {} missed DA blocks", missed_da_blocks_count);
                        for i in 1..=missed_da_blocks_count {
                            let needed_da_block_height = last_used_l1_height + i;
                            let da_block = self
                                .da_service
                                .get_block_at(needed_da_block_height)
                                .await
                                .map_err(|e| anyhow!(e))?;

                            debug!("Created an empty L2 for L1={}", needed_da_block_height);
                            if let Err(e) = self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::Empty, &pg_pool, last_used_l1_height).await {
                                error!("Sequencer error: {}", e);
                            }
                        }
                        missed_da_blocks_count = 0;
                    }

                    let l1_fee_rate_range =
                        match get_l1_fee_rate_range::<C, Da>(self.storage.clone(), self.soft_confirmation_rule_enforcer.clone()) {
                            Ok(fee_rate_range) => fee_rate_range,
                            Err(e) => {
                                error!("Could not fetch L1 fee rate range: {}", e);
                                continue;
                            }
                        };
                    let l1_fee_rate = l1_fee_rate.clamp(*l1_fee_rate_range.start(), *l1_fee_rate_range.end());
                    match self.produce_l2_block(last_finalized_block.clone(), l1_fee_rate, L2BlockMode::NotEmpty, &pg_pool, last_used_l1_height).await {
                        Ok((l1_block_number, state_diff_threshold_reached)) => {
                            last_used_l1_height = l1_block_number;

                            if da_commitment_tx.unbounded_send(state_diff_threshold_reached).is_err() {
                                error!("Commitment thread is dead!");
                            }
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    }
                },
                // If sequencer is in production mode, it will build a block every 2 seconds
                _ = interval.tick(), if !self.config.test_mode => {
                    // By default, we produce a non-empty block IFF we were caught up all the way to
                    // last_finalized_block. If there are missed DA blocks, we start producing
                    // empty blocks at ~2 second rate, 1 L2 block per respective missed DA block
                    // until we know we caught up with L1.
                    let da_block = last_finalized_block.clone();

                    if missed_da_blocks_count > 0 {
                        debug!("We have {} missed DA blocks", missed_da_blocks_count);
                        for i in 1..=missed_da_blocks_count {
                            let needed_da_block_height = last_used_l1_height + i;
                            let da_block = self
                                .da_service
                                .get_block_at(needed_da_block_height)
                                .await
                                .map_err(|e| anyhow!(e))?;

                            debug!("Created an empty L2 for L1={}", needed_da_block_height);
                            if let Err(e) = self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::Empty, &pg_pool, last_used_l1_height).await {
                                error!("Sequencer error: {}", e);
                            }
                        }
                        missed_da_blocks_count = 0;
                    }

                    let l1_fee_rate_range =
                        match get_l1_fee_rate_range::<C, Da>(self.storage.clone(), self.soft_confirmation_rule_enforcer.clone()) {
                            Ok(fee_rate_range) => fee_rate_range,
                            Err(e) => {
                                error!("Could not fetch L1 fee rate range: {}", e);
                                continue;
                            }
                        };
                    let l1_fee_rate = l1_fee_rate.clamp(*l1_fee_rate_range.start(), *l1_fee_rate_range.end());

                    let instant = Instant::now();
                    match self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::NotEmpty, &pg_pool, last_used_l1_height).await {
                        Ok((l1_block_number, state_diff_threshold_reached)) => {
                            // Set the next iteration's wait time to produce a block based on the
                            // previous block's execution time.
                            // This is mainly to make sure we account for the execution time to
                            // achieve consistent 2-second block production.
                            parent_block_exec_time = instant.elapsed();

                            last_used_l1_height = l1_block_number;

                            if da_commitment_tx.unbounded_send(state_diff_threshold_reached).is_err() {
                                error!("Commitment thread is dead!");
                            }
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    };
                }
            }
        }
    }

    fn get_best_transactions(
        &self,
    ) -> anyhow::Result<
        Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>>,
    > {
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

        Ok(best_txs_with_base_fee)
    }

    /// Signs batch of messages with sovereign priv key turns them into a sov blob
    /// Returns a single sovereign transaction made up of multiple ethereum transactions
    fn make_blob(
        &mut self,
        raw_message: Vec<u8>,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<Vec<u8>> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce(working_set)?;
        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        let transaction =
            Transaction::<C>::new_signed_tx(&self.sov_tx_signer_priv_key, raw_message, 0, nonce);
        borsh::to_vec(&transaction).map_err(|e| anyhow!(e))
    }

    /// Signs necessary info and returns a BlockTemplate
    fn sign_soft_confirmation_batch(
        &mut self,
        soft_confirmation: UnsignedSoftConfirmationBatch,
        prev_soft_confirmation_hash: [u8; 32],
    ) -> anyhow::Result<SignedSoftConfirmationBatch> {
        let raw = borsh::to_vec(&soft_confirmation).map_err(|e| anyhow!(e))?;

        let hash = <C as sov_modules_api::Spec>::Hasher::digest(raw.as_slice()).into();

        let signature = self.sov_tx_signer_priv_key.sign(&raw);
        let pub_key = self.sov_tx_signer_priv_key.pub_key();
        Ok(SignedSoftConfirmationBatch::new(
            hash,
            prev_soft_confirmation_hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.txs(),
            soft_confirmation.deposit_data(),
            borsh::to_vec(&signature).map_err(|e| anyhow!(e))?,
            borsh::to_vec(&pub_key).map_err(|e| anyhow!(e))?,
            soft_confirmation.timestamp(),
        ))
    }

    /// Fetches nonce from state
    fn get_nonce(&self, working_set: &mut WorkingSet<C>) -> anyhow::Result<u64> {
        let accounts = Accounts::<C>::default();

        match accounts
            .get_account(self.sov_tx_signer_priv_key.pub_key(), working_set)
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
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
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
                recover_raw_transaction(reth_primitives::Bytes::from(tx.tx.as_slice().to_vec()))?;
            let pooled_tx = EthPooledTransaction::from_recovered_pooled_transaction(recovered);

            let _ = self.mempool.add_external_transaction(pooled_tx).await?;
        }
        Ok(())
    }

    pub async fn sync_commitments_from_db(
        &self,
        pg_connector: PostgresConnector,
    ) -> Result<(), anyhow::Error> {
        let db_commitment = match pg_connector.get_last_commitment().await? {
            Some(comm) => comm,
            // ignore if postgres is out of sync
            None => return Ok(()),
        };
        let ledger_commitment_l2_height = self
            .ledger_db
            .get_last_sequencer_commitment_l2_height()?
            .unwrap_or_default();
        if ledger_commitment_l2_height.0 >= db_commitment.l2_end_height {
            return Ok(());
        }

        self.ledger_db
            .set_last_sequencer_commitment_l2_height(BatchNumber(db_commitment.l2_end_height))?;

        Ok(())
    }

    fn get_account_updates(&self) -> Result<Vec<ChangedAccount>, anyhow::Error> {
        let head = self
            .db_provider
            .last_block()?
            .expect("Unrecoverable: Head must exist");

        let addresses: HashSet<Address> = match head.transactions {
            reth_rpc_types::BlockTransactions::Full(ref txs) => {
                txs.iter().map(|tx| tx.from).collect()
            }
            _ => panic!("Block should have full transactions"),
        };

        let mut updates = vec![];

        for address in addresses {
            let account = self
                .db_provider
                .basic_account(address)?
                .expect("Account must exist");
            updates.push(ChangedAccount {
                address,
                nonce: account.nonce,
                balance: account.balance,
            });
        }

        Ok(updates)
    }

    fn merge_state_diffs(&self, old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
        let mut new_diff_map = HashMap::<Vec<u8>, Option<Vec<u8>>>::from_iter(old_diff);

        new_diff_map.extend(new_diff);
        new_diff_map.into_iter().collect()
    }
}

fn get_l1_fee_rate_range<C, Da>(
    storage: C::Storage,
    rule_enforcer: SoftConfirmationRuleEnforcer<C, Da::Spec>,
) -> Result<RangeInclusive<u128>, anyhow::Error>
where
    C: Context,
    Da: DaService,
{
    let mut working_set = WorkingSet::<C>::new(storage);

    rule_enforcer
        .get_next_min_max_l1_fee_rate(&mut working_set)
        .map_err(|e| anyhow::anyhow!("Error reading min max l1 fee rate: {}", e))
}

async fn da_block_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<L1Data<Da>>,
    loop_interval: u64,
) where
    Da: DaService,
{
    loop {
        let l1_data = match get_da_block_data(da_service.clone()).await {
            Ok(l1_data) => l1_data,
            Err(e) => {
                error!("Could not fetch L1 data, {}", e);
                continue;
            }
        };

        let _ = sender.send(l1_data).await;

        sleep(Duration::from_millis(loop_interval)).await;
    }
}

async fn get_da_block_data<Da>(da_service: Arc<Da>) -> anyhow::Result<L1Data<Da>>
where
    Da: DaService,
{
    let last_finalized_height = match da_service.get_last_finalized_block_header().await {
        Ok(header) => header.height(),
        Err(e) => {
            return Err(anyhow!("Finalized L1 height: {}", e));
        }
    };

    let last_finalized_block = match da_service.get_block_at(last_finalized_height).await {
        Ok(block) => block,
        Err(e) => {
            return Err(anyhow!("Finalized L1 block: {}", e));
        }
    };

    debug!(
        "Sequencer: last finalized L1 height: {:?}",
        last_finalized_height
    );

    let l1_fee_rate = match da_service.get_fee_rate().await {
        Ok(fee_rate) => fee_rate,
        Err(e) => {
            return Err(anyhow!("L1 fee rate: {}", e));
        }
    };

    Ok((last_finalized_block, l1_fee_rate))
}
