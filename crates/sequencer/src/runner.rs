use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{RollupPublicKeys, RpcConfig, SequencerConfig};
use citrea_evm::{CallMessage, Evm, RlpEvmTransaction, MIN_TRANSACTION_GAS};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_stf::runtime::Runtime;
use digest::Digest;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use jsonrpsee::server::{BatchRequestConfig, RpcServiceBuilder, ServerBuilder};
use jsonrpsee::RpcModule;
use parking_lot::Mutex;
use reth_primitives::{Address, IntoRecoveredTransaction, TxHash};
use reth_provider::{AccountReader, BlockReaderIdExt};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, ChangedAccount, EthPooledTransaction,
    PoolTransaction, ValidPoolTransaction,
};
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    Context, EncodeCall, PrivateKey, SignedSoftConfirmation, SlotData, StateDiff,
    UnsignedSoftConfirmation, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::InitVariant;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;

use crate::commitment::CommitmentService;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::rpc::{create_rpc_module, RpcContext};
use crate::utils::recover_raw_transaction;

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
    sequencer_da_pub_key: Vec<u8>,
    rpc_config: RpcConfig,
    fork_manager: ForkManager,
    soft_confirmation_tx: broadcast::Sender<u64>,
    task_manager: TaskManager<()>,
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
    DB: SequencerLedgerOps + Send + Sync + Clone + 'static,
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
        fork_manager: ForkManager,
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

        let task_manager = TaskManager::default();

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
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            rpc_config,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        })
    }

    pub async fn start_rpc_server(
        &mut self,
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

        let middleware = tower::ServiceBuilder::new().layer(citrea_common::rpc::get_cors_layer());
        //  .layer(citrea_common::rpc::get_healthcheck_proxy_layer());
        let rpc_middleware = RpcServiceBuilder::new().layer_fn(citrea_common::rpc::Logger);

        self.task_manager.spawn(|cancellation_token| async move {
            let server = ServerBuilder::default()
                .max_connections(max_connections)
                .max_subscriptions_per_connection(max_subscriptions_per_connection)
                .max_request_body_size(max_request_body_size)
                .max_response_body_size(max_response_body_size)
                .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
                .set_http_middleware(middleware)
                .set_rpc_middleware(rpc_middleware)
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
                    cancellation_token.cancelled().await;
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
        soft_confirmation_info: HookSoftConfirmationInfo,
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);

        tracing::subscriber::with_default(silent_subscriber, || {
            match self.stf.begin_soft_confirmation(
                pub_key,
                prestate.clone(),
                Default::default(),
                &da_block_header,
                &soft_confirmation_info,
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
                                >>::encode_call(
                                    call_txs
                                );
                                let signed_blob =
                                    self.make_blob(raw_message, &mut working_set_to_discard)?;

                                let txs = vec![signed_blob.clone()];

                                let (sc_workspace, _) = self.stf.apply_soft_confirmation_txs(
                                    soft_confirmation_info.clone(),
                                    txs.clone(),
                                    working_set_to_discard,
                                );

                                working_set_to_discard = sc_workspace;

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
                            let l1_fee_failed_txs = evm.get_l1_fee_failed_txs(
                                &mut working_set_to_discard.accessory_state(),
                            );

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
        })
    }

    async fn produce_l2_block(
        &mut self,
        da_block: <Da as DaService>::FilteredBlock,
        l1_fee_rate: u128,
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(u64, u64, StateDiff)> {
        let da_height = da_block.header().height();
        let (l2_height, l1_height) = match self
            .ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
        {
            Some((l2_height, sb)) => (l2_height.0 + 1, sb.da_slot_height),
            None => (1, da_height),
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
            .fetch_deposits(self.config.deposit_mempool_fetch_limit);

        let active_fork_spec = self.fork_manager.active_fork().spec_id;

        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height,
            da_slot_height: da_block.header().height(),
            da_slot_hash: da_block.header().hash().into(),
            da_slot_txs_commitment: da_block.header().txs_commitment().into(),
            pre_state_root: self.state_root.clone().as_ref().to_vec(),
            deposit_data: deposit_data.clone(),
            current_spec: active_fork_spec,
            pub_key: pub_key.clone(),
            l1_fee_rate,
            timestamp,
        };

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .map_err(Into::<anyhow::Error>::into)?;
        debug!(
            "Applying soft confirmation on DA block: {}",
            hex::encode(da_block.header().hash().into())
        );

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
                soft_confirmation_info.clone(),
                l2_block_mode,
            )
            .await?;

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)
            .map_err(Into::<anyhow::Error>::into)?;

        // Execute the selected transactions
        match self.stf.begin_soft_confirmation(
            &pub_key,
            prestate.clone(),
            Default::default(),
            da_block.header(),
            &soft_confirmation_info,
        ) {
            (Ok(()), mut batch_workspace) => {
                let mut txs = vec![];
                let mut tx_receipts = vec![];

                let evm_txs_count = txs_to_run.len();
                if evm_txs_count > 0 {
                    let call_txs = CallMessage { txs: txs_to_run };
                    let raw_message =
                        <Runtime<C, Da::Spec> as EncodeCall<citrea_evm::Evm<C>>>::encode_call(
                            call_txs,
                        );
                    let signed_blob = self.make_blob(raw_message, &mut batch_workspace)?;
                    txs.push(signed_blob);

                    (batch_workspace, tx_receipts) = self.stf.apply_soft_confirmation_txs(
                        soft_confirmation_info,
                        txs.clone(),
                        batch_workspace,
                    );
                }

                // create the unsigned batch with the txs then sign th sc
                let unsigned_batch = UnsignedSoftConfirmation::new(
                    l2_height,
                    da_block.header().height(),
                    da_block.header().hash().into(),
                    da_block.header().txs_commitment().into(),
                    txs,
                    deposit_data.clone(),
                    l1_fee_rate,
                    timestamp,
                );

                let mut signed_soft_confirmation =
                    self.sign_soft_confirmation_batch(unsigned_batch, self.batch_hash)?;

                let (soft_confirmation_receipt, checkpoint) = self.stf.end_soft_confirmation(
                    active_fork_spec,
                    self.state_root.as_ref().to_vec(),
                    self.sequencer_pub_key.as_ref(),
                    &mut signed_soft_confirmation,
                    tx_receipts,
                    batch_workspace,
                );

                let soft_confirmation_receipt = soft_confirmation_receipt?;

                // Finalize soft confirmation
                let soft_confirmation_result = self.stf.finalize_soft_confirmation(
                    active_fork_spec,
                    soft_confirmation_receipt,
                    checkpoint,
                    prestate,
                    &mut signed_soft_confirmation,
                );

                let receipt = soft_confirmation_result.soft_confirmation_receipt;

                if soft_confirmation_result.state_root.as_ref() == self.state_root.as_ref() {
                    bail!("Max L2 blocks per L1 is reached for the current L1 block. State root is the same as before, skipping");
                }

                trace!(
                    "State root after applying slot: {:?}",
                    soft_confirmation_result.state_root
                );

                let next_state_root = soft_confirmation_result.state_root;

                self.storage_manager
                    .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

                // TODO: this will only work for mock da
                // when https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218
                // is merged, rpc will access up to date storage then we won't need to finalize rigth away.
                // however we need much better DA + finalization logic here
                self.storage_manager.finalize_l2(l2_height)?;

                self.ledger_db
                    .commit_soft_confirmation(next_state_root.as_ref(), receipt, true)?;

                // connect L1 and L2 height
                self.ledger_db.extend_l2_range_of_l1_slot(
                    SlotNumber(da_block.header().height()),
                    BatchNumber(l2_height),
                )?;

                // Register this new block with the fork manager to active
                // the new fork on the next block
                self.fork_manager.register_block(l2_height)?;

                let l1_height = da_block.header().height();
                info!(
                    "New block #{}, DA #{}, Tx count: #{}",
                    l2_height, l1_height, evm_txs_count,
                );

                self.state_root = next_state_root;
                self.batch_hash = signed_soft_confirmation.hash();

                let mut txs_to_remove = self.db_provider.last_block_tx_hashes()?;
                txs_to_remove.extend(l1_fee_failed_txs);

                self.mempool.remove_transactions(txs_to_remove.clone());

                let account_updates = self.get_account_updates()?;

                self.mempool.update_accounts(account_updates);

                let txs = txs_to_remove
                    .iter()
                    .map(|tx_hash| tx_hash.to_vec())
                    .collect::<Vec<Vec<u8>>>();
                if let Err(e) = self.ledger_db.remove_mempool_txs(txs) {
                    warn!("Failed to remove txs from mempool: {:?}", e);
                }

                Ok((
                    l2_height,
                    da_block.header().height(),
                    soft_confirmation_result.state_diff,
                ))
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

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // TODO: hotfix for mock da
        self.da_service
            .get_block_at(1)
            .await
            .map_err(|e| anyhow!(e))?;

        match self.restore_mempool().await {
            Ok(()) => debug!("Sequencer: Mempool restored"),
            Err(e) => {
                warn!("Sequencer: Mempool restore error: {:?}", e);
            }
        }

        let (mut last_finalized_block, mut l1_fee_rate) =
            match get_da_block_data(self.da_service.clone()).await {
                Ok(l1_data) => l1_data,
                Err(e) => {
                    error!("{}", e);
                    return Err(e);
                }
            };
        let mut last_finalized_height = last_finalized_block.header().height();

        let mut last_used_l1_height = match self.ledger_db.get_head_soft_confirmation() {
            Ok(Some((_, sb))) => sb.da_slot_height,
            Ok(None) => last_finalized_height, // starting for the first time
            Err(e) => {
                return Err(anyhow!("previous L1 height: {}", e));
            }
        };

        debug!("Sequencer: Last used L1 height: {:?}", last_used_l1_height);

        // Setup required workers to update our knowledge of the DA layer every X seconds (configurable).
        let (da_height_update_tx, mut da_height_update_rx) = mpsc::channel(1);
        let (da_commitment_tx, da_commitment_rx) = unbounded::<(u64, StateDiff)>();

        let mut commitment_service = CommitmentService::new(
            self.ledger_db.clone().into(),
            self.da_service.clone(),
            self.sequencer_da_pub_key.clone(),
            self.config.min_soft_confirmations_per_commitment,
            da_commitment_rx,
        );
        if self.batch_hash != [0; 32] {
            // Resubmit if there were pending commitments on restart, skip it on first init
            commitment_service.resubmit_pending_commitments().await?;
        }
        self.task_manager
            .spawn(|cancellation_token| commitment_service.run(cancellation_token));

        self.task_manager.spawn(|cancellation_token| {
            da_block_monitor(
                self.da_service.clone(),
                da_height_update_tx,
                self.config.da_update_interval_ms,
                cancellation_token,
            )
        });

        let target_block_time = Duration::from_millis(self.config.block_production_interval_ms);

        // In case the sequencer falls behind on DA blocks, we need to produce at least 1
        // empty block per DA block. Which means that we have to keep count of missed blocks
        // and only resume normal operations once the sequencer has caught up.
        let mut missed_da_blocks_count =
            self.da_blocks_missed(last_finalized_height, last_used_l1_height);

        let mut block_production_tick = tokio::time::interval(target_block_time);
        block_production_tick.tick().await;

        loop {
            tokio::select! {
                // Receive updates from DA layer worker.
                l1_data = da_height_update_rx.recv() => {
                    // Stop receiving updates from DA layer until we have caught up.
                    if missed_da_blocks_count > 0 {
                        continue;
                    }
                    if let Some(l1_data) = l1_data {
                        (last_finalized_block, l1_fee_rate) = l1_data;
                        last_finalized_height = last_finalized_block.header().height();

                        missed_da_blocks_count = self.da_blocks_missed(last_finalized_height, last_used_l1_height);
                    }
                },
                // If sequencer is in test mode, it will build a block every time it receives a message
                // The RPC from which the sender can be called is only registered for test mode. This means
                // that evey though we check the receiver here, it'll never be "ready" to be consumed unless in test mode.
                _ = self.l2_force_block_rx.next(), if self.config.test_mode => {
                    if missed_da_blocks_count > 0 {
                        if let Err(e) = self.process_missed_da_blocks(missed_da_blocks_count, last_used_l1_height, l1_fee_rate).await {
                            error!("Sequencer error: {}", e);
                            // we never want to continue if we have missed blocks
                            return Err(e);
                        }
                        missed_da_blocks_count = 0;
                    }

                    match self.produce_l2_block(last_finalized_block.clone(), l1_fee_rate, L2BlockMode::NotEmpty).await {
                        Ok((l2_height, l1_block_number, state_diff)) => {
                            last_used_l1_height = l1_block_number;

                            // Only errors when there are no receivers
                            let _ = self.soft_confirmation_tx.send(l2_height);

                            let _ = da_commitment_tx.unbounded_send((l2_height, state_diff));
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    }
                },
                // If sequencer is in production mode, it will build a block every 2 seconds
                _ = block_production_tick.tick(), if !self.config.test_mode => {
                    // By default, we produce a non-empty block IFF we were caught up all the way to
                    // last_finalized_block. If there are missed DA blocks, we start producing
                    // empty blocks at ~2 second rate, 1 L2 block per respective missed DA block
                    // until we know we caught up with L1.
                    let da_block = last_finalized_block.clone();

                    if missed_da_blocks_count > 0 {
                        if let Err(e) = self.process_missed_da_blocks(missed_da_blocks_count, last_used_l1_height, l1_fee_rate).await {
                            error!("Sequencer error: {}", e);
                            // we never want to continue if we have missed blocks
                            return Err(e);
                        }
                        missed_da_blocks_count = 0;
                    }


                    match self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::NotEmpty).await {
                        Ok((l2_height, l1_block_number, state_diff)) => {
                            last_used_l1_height = l1_block_number;

                            // Only errors when there are no receivers
                            let _ = self.soft_confirmation_tx.send(l2_height);

                            let _ = da_commitment_tx.unbounded_send((l2_height, state_diff));
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    };
                },
                _ = signal::ctrl_c() => {
                    info!("Shutting down sequencer");
                    self.task_manager.abort().await;
                    return Ok(());
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

        let base_fee = calculate_next_block_base_fee(
            latest_header.gas_used as u128,
            latest_header.gas_limit as u128,
            latest_header.base_fee_per_gas,
            cfg.base_fee_params,
        )
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
        soft_confirmation: UnsignedSoftConfirmation,
        prev_soft_confirmation_hash: [u8; 32],
    ) -> anyhow::Result<SignedSoftConfirmation> {
        let raw = borsh::to_vec(&soft_confirmation).map_err(|e| anyhow!(e))?;

        let hash = <C as sov_modules_api::Spec>::Hasher::digest(raw.as_slice()).into();

        let signature = self.sov_tx_signer_priv_key.sign(&raw);
        let pub_key = self.sov_tx_signer_priv_key.pub_key();
        Ok(SignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
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
    async fn create_rpc_context(&self) -> RpcContext<C, DB> {
        let l2_force_block_tx = self.l2_force_block_tx.clone();

        RpcContext {
            mempool: self.mempool.clone(),
            deposit_mempool: self.deposit_mempool.clone(),
            l2_force_block_tx,
            storage: self.storage.clone(),
            ledger: self.ledger_db.clone(),
            test_mode: self.config.test_mode,
        }
    }

    /// Updates the given RpcModule with Sequencer methods.
    pub async fn register_rpc_methods(
        &self,
        mut rpc_methods: jsonrpsee::RpcModule<()>,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let rpc_context = self.create_rpc_context().await;
        let rpc = create_rpc_module(rpc_context);
        rpc_methods.merge(rpc)?;
        Ok(rpc_methods)
    }

    pub async fn restore_mempool(&self) -> Result<(), anyhow::Error> {
        let mempool_txs = self.ledger_db.get_mempool_txs()?;
        for (_, tx) in mempool_txs {
            let recovered =
                recover_raw_transaction(reth_primitives::Bytes::from(tx.as_slice().to_vec()))?;
            let pooled_tx = EthPooledTransaction::from_pooled(recovered);

            let _ = self.mempool.add_external_transaction(pooled_tx).await?;
        }
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

    pub async fn process_missed_da_blocks(
        &mut self,
        missed_da_blocks_count: u64,
        last_used_l1_height: u64,
        l1_fee_rate: u128,
    ) -> anyhow::Result<()> {
        debug!("We have {} missed DA blocks", missed_da_blocks_count);
        let exponential_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(50))
            .with_max_elapsed_time(Some(Duration::from_secs(1)))
            .build();
        for i in 1..=missed_da_blocks_count {
            let needed_da_block_height = last_used_l1_height + i;

            // if we can't fetch da block and fail to produce a block the caller will return Err stopping
            // the sequencer. This is very problematic.
            // Hence, we retry fetching the DA block and producing the L2 block.

            let da_service = self.da_service.as_ref();
            let da_block = retry_backoff(exponential_backoff.clone(), || async move {
                da_service
                    .get_block_at(needed_da_block_height)
                    .await
                    .map_err(|e| backoff::Error::Transient {
                        err: anyhow!(e),
                        retry_after: None,
                    })
            })
            .await?;

            debug!("Created an empty L2 for L1={}", needed_da_block_height);
            self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::Empty)
                .await?;
        }

        Ok(())
    }

    pub fn da_blocks_missed(
        &self,
        last_finalized_block_height: u64,
        last_used_l1_height: u64,
    ) -> u64 {
        if last_finalized_block_height <= last_used_l1_height {
            return 0;
        }
        let skipped_blocks = last_finalized_block_height - last_used_l1_height - 1;
        if skipped_blocks > 0 {
            // This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
            warn!(
                "Sequencer is falling behind on L1 blocks by {:?} blocks",
                skipped_blocks
            );
        }
        // Missed DA blocks means that we produce n - 1 empty blocks, 1 per missed DA block.
        skipped_blocks
    }
}

async fn da_block_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<L1Data<Da>>,
    loop_interval: u64,
    cancellation_token: CancellationToken,
) where
    Da: DaService,
{
    loop {
        tokio::select! {
            biased;
            _ = cancellation_token.cancelled() => {
                return;
            }
            l1_data = get_da_block_data(da_service.clone()) => {
                let l1_data = match l1_data {
                    Ok(l1_data) => l1_data,
                    Err(e) => {
                        error!("Could not fetch L1 data, {}", e);
                        continue;
                    }
                };

                let _ = sender.send(l1_data).await;

                sleep(Duration::from_millis(loop_interval)).await;
            },
        }
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
