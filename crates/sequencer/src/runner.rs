use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxHash};
use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::backup::BackupManager;
use citrea_common::utils::soft_confirmation_to_receipt;
use citrea_common::{InitParams, RollupPublicKeys, SequencerConfig};
use citrea_evm::{CallMessage, RlpEvmTransaction, MIN_TRANSACTION_GAS};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use parking_lot::Mutex;
use reth_execution_types::ChangedAccount;
use reth_provider::{AccountReader, BlockReaderIdExt};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, EthPooledTransaction, PoolTransaction,
    ValidPoolTransaction,
};
use soft_confirmation_rule_enforcer::CallMessage as RuleEnforcerCallMessage;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_modules_api::default_signature::k256_private_key::K256PrivateKey;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::transaction::{PreFork2Transaction, Transaction};
use sov_modules_api::{
    EncodeCall, PrivateKey, SignedSoftConfirmation, SlotData, Spec, SpecId, StateDiff,
    UnsignedSoftConfirmation, UnsignedSoftConfirmationV1, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::{ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::ProverStorage;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
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
use crate::metrics::SEQUENCER_METRICS;
use crate::utils::recover_raw_transaction;

type StfTransaction<Da> =
    <StfBlueprint<DefaultContext, Da, CitreaRuntime<DefaultContext, Da>> as StateTransitionFunction<Da>>::Transaction;

/// Represents information about the current DA state.
///
/// Contains previous height, latest finalized block and fee rate.
type L1Data<Da> = (<Da as DaService>::FilteredBlock, u128);

pub struct CitreaSequencer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    da_service: Arc<Da>,
    mempool: Arc<CitreaMempool>,
    // TODO: Use k256 private key here before mainnet
    sov_tx_signer_priv_key: Vec<u8>,
    l2_force_block_rx: UnboundedReceiver<()>,
    db_provider: DbProvider,
    ledger_db: DB,
    config: SequencerConfig,
    stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    storage_manager: ProverStorageManager<Da::Spec>,
    state_root: StorageRootHash,
    soft_confirmation_hash: SoftConfirmationHash,
    sequencer_pub_key: Vec<u8>,
    sequencer_k256_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    fork_manager: ForkManager<'static>,
    soft_confirmation_tx: broadcast::Sender<u64>,
    backup_manager: Arc<BackupManager>,
}

enum L2BlockMode {
    Empty,
    NotEmpty,
}

impl<Da, DB> CitreaSequencer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Sync + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        da_service: Arc<Da>,
        config: SequencerConfig,
        init_params: InitParams,
        stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
        storage_manager: ProverStorageManager<Da::Spec>,
        public_keys: RollupPublicKeys,
        ledger_db: DB,
        db_provider: DbProvider,
        mempool: Arc<CitreaMempool>,
        deposit_mempool: Arc<Mutex<DepositDataMempool>>,
        fork_manager: ForkManager<'static>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        backup_manager: Arc<BackupManager>,
        l2_force_block_rx: UnboundedReceiver<()>,
    ) -> anyhow::Result<Self> {
        let sov_tx_signer_priv_key = hex::decode(&config.private_key)?;

        Ok(Self {
            da_service,
            mempool,
            sov_tx_signer_priv_key,
            l2_force_block_rx,
            db_provider,
            ledger_db,
            config,
            stf,
            deposit_mempool,
            storage_manager,
            state_root: init_params.state_root,
            soft_confirmation_hash: init_params.batch_hash,
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_k256_pub_key: public_keys.sequencer_k256_public_key,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            fork_manager,
            soft_confirmation_tx,
            backup_manager,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn dry_run_transactions(
        &mut self,
        mut transactions: Box<
            dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>,
        >,
        pub_key: &[u8],
        prestate: ProverStorage<SnapshotManager>,
        da_block_header: <<Da as DaService>::Spec as DaSpec>::BlockHeader,
        soft_confirmation_info: HookSoftConfirmationInfo,
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        let start = Instant::now();

        let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);

        tracing::subscriber::with_default(silent_subscriber, || {
            let mut working_set_to_discard = WorkingSet::new(prestate.clone());

            match self.stf.begin_soft_confirmation(
                pub_key,
                &mut working_set_to_discard,
                &da_block_header,
                &soft_confirmation_info,
            ) {
                Ok(_) => {
                    match l2_block_mode {
                        L2BlockMode::NotEmpty => {
                            // Normally, transactions.mark_invalid() calls would give us the same
                            // functionality as invalid_senders, however,
                            // in this version of reth, mark_invalid uses transaction.hash() to mark invalid
                            // which is not desired. This was fixed in later versions, but we can not update
                            // to those versions because we have to lock our Rust version to 1.81.
                            //
                            // When a tx is rejected, its sender is added to invalid_senders set
                            // because other transactions from the same sender now cannot be included in the block
                            // since they are auto rejected due to the nonce gap.
                            let mut invalid_senders = HashSet::new();

                            let mut all_txs = vec![];
                            let mut l1_fee_failed_txs = vec![];

                            // using .next() instead of a for loop because its the intended
                            // behaviour for the BestTransactions implementations
                            // when we update reth we'll need to call transactions.mark_invalid()
                            #[allow(clippy::while_let_on_iterator)]
                            while let Some(evm_tx) = transactions.next() {
                                if invalid_senders.contains(&evm_tx.transaction_id.sender) {
                                    continue;
                                }

                                let mut buf = vec![];
                                evm_tx
                                    .to_recovered_transaction()
                                    .into_signed()
                                    .encode_2718(&mut buf);
                                let rlp_tx = RlpEvmTransaction { rlp: buf };

                                let call_txs = CallMessage {
                                    txs: vec![rlp_tx.clone()],
                                };
                                let raw_message =
                                    <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                                        citrea_evm::Evm<DefaultContext>,
                                    >>::encode_call(call_txs);
                                let signed_blob = self.make_blob(
                                    raw_message.clone(),
                                    &mut working_set_to_discard,
                                    soft_confirmation_info.current_spec(),
                                )?;

                                let signed_tx = self.sign_tx(
                                    raw_message,
                                    &mut working_set_to_discard,
                                    soft_confirmation_info.current_spec(),
                                )?;

                                let txs = vec![signed_blob.clone()];
                                let txs_new = vec![signed_tx];

                                let mut working_set =
                                    working_set_to_discard.checkpoint().to_revertable();

                                match self.stf.apply_soft_confirmation_txs(
                                    soft_confirmation_info.clone(),
                                    &txs,
                                    &txs_new,
                                    &mut working_set,
                                ) {
                                    Ok(result) => result,
                                    Err(e) => match e {
                                        // Since this is the sequencer, it should never get a soft confirmation error or a hook error
                                        sov_rollup_interface::stf::StateTransitionError::SoftConfirmationError(soft_confirmation_error) => panic!("Soft confirmation error: {:?}", soft_confirmation_error),
                                        sov_rollup_interface::stf::StateTransitionError::HookError(soft_confirmation_hook_error) => panic!("Hook error: {:?}", soft_confirmation_hook_error),
                                        sov_rollup_interface::stf::StateTransitionError::ModuleCallError(soft_confirmation_module_call_error) => match soft_confirmation_module_call_error {
                                            // if we are exceeding block gas limit with a transaction
                                            // we should inspect the gas usage and act accordingly
                                            // if there is room for another transaction
                                            // keep trying txs
                                            // if not, break
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                                                cumulative_gas,
                                                tx_gas_used: _,
                                                block_gas_limit
                                            } => {
                                               if block_gas_limit - cumulative_gas < MIN_TRANSACTION_GAS {
                                                break;
                                               } else {
                                                invalid_senders.insert(evm_tx.transaction_id.sender);
                                                working_set_to_discard = working_set.revert().to_revertable();
                                                continue;
                                               }
                                            },
                                            // we configure mempool to never accept blob transactions
                                            // to mitigate potential bugs in reth-mempool we should look into continue instead of panicking here
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTxTypeNotSupported(_) => panic!("got unsupported tx type"),
                                            // Discard tx if it fails to execute
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTransactionExecutionError => {
                                                invalid_senders.insert(evm_tx.transaction_id.sender);
                                                working_set_to_discard = working_set.revert().to_revertable();
                                                continue;
                                            },
                                            // we won't try to execute system transactions here
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmMisplacedSystemTx => panic!("tried to execute system transaction"),
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmNotEnoughFundsForL1Fee => {
                                                l1_fee_failed_txs.push(*evm_tx.hash());
                                                invalid_senders.insert(evm_tx.transaction_id.sender);
                                                working_set_to_discard = working_set.revert().to_revertable();
                                                continue;
                                            },
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTxNotSerializable => panic!("Fed a non-serializable tx"),
                                            // we don't call the rule enforcer in the sequencer -- yet at least
                                            sov_modules_api::SoftConfirmationModuleCallError::RuleEnforcerUnauthorized => unreachable!(),
                                        },
                                    },
                                };

                                // if no errors
                                // we can include the transaction in the block
                                working_set_to_discard = working_set.checkpoint().to_revertable();
                                all_txs.push(rlp_tx);
                            }
                            SEQUENCER_METRICS.dry_run_execution.record(
                                Instant::now()
                                    .saturating_duration_since(start)
                                    .as_secs_f64(),
                            );

                            Ok((all_txs, l1_fee_failed_txs))
                        }
                        L2BlockMode::Empty => Ok((vec![], vec![])),
                    }
                }
                Err(err) => {
                    warn!(
                    "DryRun: Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
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
        let start = Instant::now();
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

        let deposit_data = self
            .deposit_mempool
            .lock()
            .fetch_deposits(self.config.deposit_mempool_fetch_limit);

        // Register this new block with the fork manager to active
        // the new fork on the next block
        self.fork_manager.register_block(l2_height)?;

        let active_fork_spec = self.fork_manager.active_fork().spec_id;
        let pub_key = if active_fork_spec >= SpecId::Fork2 {
            borsh::to_vec(
                &K256PrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice())
                    .unwrap()
                    .pub_key(),
            )?
        } else {
            borsh::to_vec(
                &DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice())
                    .unwrap()
                    .pub_key(),
            )?
        };

        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height,
            da_slot_height: da_block.header().height(),
            da_slot_hash: da_block.header().hash().into(),
            da_slot_txs_commitment: da_block.header().txs_commitment().into(),
            pre_state_root: self.state_root,
            deposit_data: deposit_data.clone(),
            current_spec: active_fork_spec,
            pub_key: pub_key.clone(),
            l1_fee_rate,
            timestamp,
        };

        let prestate = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)?;
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
            .create_storage_on_l2_height(l2_height)?;

        let mut working_set = WorkingSet::new(prestate.clone());

        // Execute the selected transactions
        match self.stf.begin_soft_confirmation(
            &pub_key,
            &mut working_set,
            da_block.header(),
            &soft_confirmation_info,
        ) {
            Ok(_) => {
                let mut txs = vec![];
                let mut txs_new = vec![];

                let evm_txs_count = txs_to_run.len();
                if evm_txs_count > 0 {
                    let call_txs = CallMessage { txs: txs_to_run };
                    let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                        citrea_evm::Evm<DefaultContext>,
                    >>::encode_call(call_txs);
                    let signed_blob = self.make_blob(
                        raw_message.clone(),
                        &mut working_set,
                        soft_confirmation_info.current_spec(),
                    )?;
                    let signed_tx = self.sign_tx(
                        raw_message,
                        &mut working_set,
                        soft_confirmation_info.current_spec(),
                    )?;
                    txs.push(signed_blob);
                    txs_new.push(signed_tx);
                }

                // get the fork2 activation height
                // If next block activates Fork2 we should update rule enforcer authority
                // Because we use a new public key for sequencer now
                let next_fork = self.fork_manager.next_fork();
                if let Some(next_fork) = next_fork {
                    if next_fork.spec_id == SpecId::Fork2
                        && soft_confirmation_info.l2_height + 1 == next_fork.activation_height
                    {
                        let (signed_blob, signed_tx) = self.update_sequencer_authority(&mut working_set, soft_confirmation_info.current_spec()).expect("Should create and sign soft confirmation rule enforcer authority change call messages");
                        txs.push(signed_blob);
                        txs_new.push(signed_tx);
                    }
                }

                self.stf
                    .apply_soft_confirmation_txs(
                        soft_confirmation_info,
                        &txs,
                        &txs_new,
                        &mut working_set,
                    )
                    .expect("dry_run_transactions should have already checked this");

                // create the unsigned batch with the txs then sign th sc
                let unsigned_batch = UnsignedSoftConfirmation::new(
                    l2_height,
                    da_block.header().height(),
                    da_block.header().hash().into(),
                    da_block.header().txs_commitment().into(),
                    &txs,
                    &txs_new,
                    deposit_data,
                    l1_fee_rate,
                    timestamp,
                );

                let mut signed_soft_confirmation = if active_fork_spec
                    >= sov_modules_api::SpecId::Fork2
                {
                    self.sign_soft_confirmation_batch(&unsigned_batch, self.soft_confirmation_hash)?
                } else if active_fork_spec >= sov_modules_api::SpecId::Kumquat {
                    self.pre_fork2_sign_soft_confirmation_batch(
                        &unsigned_batch,
                        self.soft_confirmation_hash,
                    )?
                } else {
                    self.pre_fork1_sign_soft_confirmation_batch(
                        &unsigned_batch,
                        self.soft_confirmation_hash,
                    )?
                };

                if active_fork_spec >= SpecId::Fork2 {
                    self.stf.end_soft_confirmation(
                        active_fork_spec,
                        self.state_root,
                        self.sequencer_k256_pub_key.as_ref(),
                        &mut signed_soft_confirmation,
                        &mut working_set,
                    )?;
                } else {
                    self.stf.end_soft_confirmation(
                        active_fork_spec,
                        self.state_root,
                        self.sequencer_pub_key.as_ref(),
                        &mut signed_soft_confirmation,
                        &mut working_set,
                    )?;
                }

                // Finalize soft confirmation
                let soft_confirmation_result = self.stf.finalize_soft_confirmation(
                    active_fork_spec,
                    working_set,
                    prestate,
                    &mut signed_soft_confirmation,
                );
                let state_root_transition = soft_confirmation_result.state_root_transition;

                if state_root_transition.final_root.as_ref() == self.state_root.as_ref() {
                    bail!("Max L2 blocks per L1 is reached for the current L1 block. State root is the same as before, skipping");
                }

                trace!(
                    "State root after applying slot: {:?}",
                    state_root_transition.final_root,
                );

                let next_state_root = state_root_transition.final_root;

                self.storage_manager
                    .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

                // TODO: this will only work for mock da
                // when https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218
                // is merged, rpc will access up to date storage then we won't need to finalize right away.
                // however we need much better DA + finalization logic here
                self.storage_manager.finalize_l2(l2_height)?;

                let tx_bodies = signed_soft_confirmation.blobs().to_owned();
                let soft_confirmation_hash = signed_soft_confirmation.hash();
                let receipt = soft_confirmation_to_receipt::<DefaultContext, _, Da::Spec>(
                    signed_soft_confirmation,
                    active_fork_spec,
                );
                self.ledger_db.commit_soft_confirmation(
                    next_state_root.as_ref(),
                    receipt,
                    Some(tx_bodies),
                )?;

                // connect L1 and L2 height
                self.ledger_db.extend_l2_range_of_l1_slot(
                    SlotNumber(da_block.header().height()),
                    SoftConfirmationNumber(l2_height),
                )?;

                let l1_height = da_block.header().height();
                info!(
                    "New block #{}, DA #{}, Tx count: #{}",
                    l2_height, l1_height, evm_txs_count,
                );

                self.state_root = next_state_root;
                self.soft_confirmation_hash = soft_confirmation_hash;

                let mut txs_to_remove = self.db_provider.last_block_tx_hashes()?;
                txs_to_remove.extend(l1_fee_failed_txs);

                self.mempool.remove_transactions(txs_to_remove.clone());
                SEQUENCER_METRICS.mempool_txs.set(self.mempool.len() as f64);

                let account_updates = self.get_account_updates()?;

                self.mempool.update_accounts(account_updates);

                let txs = txs_to_remove
                    .iter()
                    .map(|tx_hash| tx_hash.to_vec())
                    .collect::<Vec<Vec<u8>>>();
                if let Err(e) = self.ledger_db.remove_mempool_txs(txs) {
                    warn!("Failed to remove txs from mempool: {:?}", e);
                }

                SEQUENCER_METRICS.block_production_execution.record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );
                SEQUENCER_METRICS.current_l2_block.set(l2_height as f64);

                Ok((
                    l2_height,
                    da_block.header().height(),
                    soft_confirmation_result.state_diff,
                ))
            }
            Err(err) => {
                warn!(
                    "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
                Err(anyhow!(
                    "Failed to apply begin soft confirmation hook: {:?}",
                    err
                ))
            }
        }
    }

    #[instrument(level = "trace", skip(self, cancellation_token), err, ret)]
    pub async fn run(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), anyhow::Error> {
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
        let (da_commitment_tx, da_commitment_rx) = unbounded_channel::<(u64, StateDiff)>();

        let mut commitment_service = CommitmentService::new(
            self.ledger_db.clone(),
            self.da_service.clone(),
            self.sequencer_da_pub_key.clone(),
            self.config.min_soft_confirmations_per_commitment,
            da_commitment_rx,
        );
        if self.soft_confirmation_hash != [0; 32] {
            // Resubmit if there were pending commitments on restart, skip it on first init
            commitment_service.resubmit_pending_commitments().await?;
        }

        tokio::spawn(commitment_service.run(cancellation_token.child_token()));

        tokio::spawn(da_block_monitor(
            self.da_service.clone(),
            da_height_update_tx,
            self.config.da_update_interval_ms,
            cancellation_token.child_token(),
        ));

        let target_block_time = Duration::from_millis(self.config.block_production_interval_ms);

        // In case the sequencer falls behind on DA blocks, we need to produce at least 1
        // empty block per DA block. Which means that we have to keep count of missed blocks
        // and only resume normal operations once the sequencer has caught up.
        let mut missed_da_blocks_count =
            self.da_blocks_missed(last_finalized_height, last_used_l1_height);

        let mut block_production_tick = tokio::time::interval(target_block_time);
        block_production_tick.tick().await;

        let backup_manager = self.backup_manager.clone();
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
                    SEQUENCER_METRICS.current_l1_block.set(last_finalized_height as f64);
                },
                // If sequencer is in test mode, it will build a block every time it receives a message
                // The RPC from which the sender can be called is only registered for test mode. This means
                // that evey though we check the receiver here, it'll never be "ready" to be consumed unless in test mode.
                _ = self.l2_force_block_rx.recv(), if self.config.test_mode => {
                    if missed_da_blocks_count > 0 {
                        if let Err(e) = self.process_missed_da_blocks(missed_da_blocks_count, last_used_l1_height, l1_fee_rate).await {
                            error!("Sequencer error: {}", e);
                            // we never want to continue if we have missed blocks
                            return Err(e);
                        }
                        missed_da_blocks_count = 0;
                    }

                    let _l2_lock = backup_manager.start_l2_processing().await;
                    match self.produce_l2_block(last_finalized_block.clone(), l1_fee_rate, L2BlockMode::NotEmpty).await {
                        Ok((l2_height, l1_block_number, state_diff)) => {
                            last_used_l1_height = l1_block_number;

                            // Only errors when there are no receivers
                            let _ = self.soft_confirmation_tx.send(l2_height);

                            let _ = da_commitment_tx.send((l2_height, state_diff));
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

                    let _l2_lock = backup_manager.start_l2_processing().await;
                    match self.produce_l2_block(da_block, l1_fee_rate, L2BlockMode::NotEmpty).await {
                        Ok((l2_height, l1_block_number, state_diff)) => {
                            last_used_l1_height = l1_block_number;

                            // Only errors when there are no receivers
                            let _ = self.soft_confirmation_tx.send(l2_height);

                            let _ = da_commitment_tx.send((l2_height, state_diff));
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    };
                },
                _ = cancellation_token.cancelled() => {
                    info!("Shutting down sequencer");
                    da_height_update_rx.close();
                    self.l2_force_block_rx.close();
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
            latest_header.gas_used,
            latest_header.gas_limit,
            latest_header
                .base_fee_per_gas
                .expect("Base fee always set in Citrea"),
            cfg.base_fee_params,
        ) as u64;

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
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        spec_id: SpecId,
    ) -> anyhow::Result<Vec<u8>> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce(working_set, spec_id)?;
        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        if spec_id >= SpecId::Kumquat {
            let transaction: Transaction = Transaction::new_signed_tx(
                &self.sov_tx_signer_priv_key,
                raw_message,
                0,
                nonce,
                spec_id,
            );
            borsh::to_vec(&transaction).map_err(|e| anyhow!(e))
        } else {
            let transaction: PreFork2Transaction<DefaultContext> =
                PreFork2Transaction::<DefaultContext>::new_signed_tx(
                    &self.sov_tx_signer_priv_key,
                    raw_message,
                    0,
                    nonce,
                );
            borsh::to_vec(&transaction).map_err(|e| anyhow!(e))
        }
    }

    fn sign_tx(
        &mut self,
        raw_message: Vec<u8>,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        spec_id: SpecId,
    ) -> anyhow::Result<StfTransaction<Da::Spec>> {
        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce(working_set, spec_id)?;
        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        let tx = Transaction::new_signed_tx(
            &self.sov_tx_signer_priv_key,
            raw_message,
            0,
            nonce,
            spec_id,
        );
        Ok(tx)
    }

    fn sign_soft_confirmation_batch<'txs>(
        &mut self,
        soft_confirmation: &'txs UnsignedSoftConfirmation<'_, StfTransaction<Da::Spec>>,
        prev_soft_confirmation_hash: [u8; 32],
    ) -> anyhow::Result<SignedSoftConfirmation<'txs, StfTransaction<Da::Spec>>> {
        let digest =
            soft_confirmation.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
        let hash = Into::<[u8; 32]>::into(digest);

        let priv_key = K256PrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();

        let signature = priv_key.sign(&hash);
        let pub_key = priv_key.pub_key();
        Ok(SignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
            hash,
            prev_soft_confirmation_hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.blobs().into(),
            soft_confirmation.txs().into(),
            soft_confirmation.deposit_data(),
            borsh::to_vec(&signature).map_err(|e| anyhow!(e))?,
            borsh::to_vec(&pub_key).map_err(|e| anyhow!(e))?,
            soft_confirmation.timestamp(),
        ))
    }

    /// Signs necessary info and returns a BlockTemplate
    fn pre_fork2_sign_soft_confirmation_batch<'txs>(
        &mut self,
        soft_confirmation: &'txs UnsignedSoftConfirmation<'_, StfTransaction<Da::Spec>>,
        prev_soft_confirmation_hash: [u8; 32],
    ) -> anyhow::Result<SignedSoftConfirmation<'txs, StfTransaction<Da::Spec>>> {
        let digest =
            soft_confirmation.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
        let hash = Into::<[u8; 32]>::into(digest);
        let priv_key = DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();

        let signature = priv_key.sign(&hash);
        let pub_key = priv_key.pub_key();
        Ok(SignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
            hash,
            prev_soft_confirmation_hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.blobs().into(),
            soft_confirmation.txs().into(),
            soft_confirmation.deposit_data(),
            borsh::to_vec(&signature).map_err(|e| anyhow!(e))?,
            borsh::to_vec(&pub_key).map_err(|e| anyhow!(e))?,
            soft_confirmation.timestamp(),
        ))
    }

    /// Old version of sign_soft_confirmation_batch
    /// TODO: Remove derive(BorshSerialize) for UnsignedSoftConfirmation
    ///   when removing this fn
    /// FIXME: ^
    fn pre_fork1_sign_soft_confirmation_batch<'txs>(
        &mut self,
        soft_confirmation: &'txs UnsignedSoftConfirmation<'_, StfTransaction<Da::Spec>>,
        prev_soft_confirmation_hash: [u8; 32],
    ) -> anyhow::Result<SignedSoftConfirmation<'txs, StfTransaction<Da::Spec>>> {
        let unsigned_sc = UnsignedSoftConfirmationV1::from(soft_confirmation.clone());
        let hash: [u8; 32] = unsigned_sc
            .hash::<<DefaultContext as Spec>::Hasher>()
            .into();

        let raw = borsh::to_vec(&unsigned_sc).map_err(|e| anyhow!(e))?;

        let priv_key = DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();

        let signature = priv_key.sign(&raw);
        let pub_key = priv_key.pub_key();

        Ok(SignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
            hash,
            prev_soft_confirmation_hash,
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.blobs().into(),
            soft_confirmation.txs().into(),
            soft_confirmation.deposit_data(),
            borsh::to_vec(&signature).map_err(|e| anyhow!(e))?,
            borsh::to_vec(&pub_key).map_err(|e| anyhow!(e))?,
            soft_confirmation.timestamp(),
        ))
    }

    /// Fetches nonce from state
    fn get_nonce(
        &self,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        spec_id: SpecId,
    ) -> anyhow::Result<u64> {
        let accounts = Accounts::<DefaultContext>::default();

        let pub_key = if spec_id >= SpecId::Fork2 {
            borsh::to_vec(
                &K256PrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice())
                    .unwrap()
                    .pub_key(),
            )?
        } else {
            borsh::to_vec(
                &DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice())
                    .unwrap()
                    .pub_key(),
            )?
        };

        match accounts
            .get_account(pub_key, spec_id, working_set)
            .map_err(|e| anyhow!("Sequencer: Failed to get sov-account: {}", e))?
        {
            AccountExists { addr: _, nonce } => Ok(nonce),
            AccountEmpty => Ok(0),
        }
    }

    pub async fn restore_mempool(&self) -> Result<(), anyhow::Error> {
        let mempool_txs = self.ledger_db.get_mempool_txs()?;
        for (_, tx) in mempool_txs {
            let recovered = recover_raw_transaction(Bytes::from(tx.as_slice().to_vec()))?;
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
            alloy_rpc_types::BlockTransactions::Full(ref txs) => {
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
            .with_initial_interval(Duration::from_millis(200))
            .with_max_elapsed_time(Some(Duration::from_secs(30)))
            .with_multiplier(1.5)
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

    fn update_sequencer_authority(
        &mut self,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        current_spec: SpecId,
    ) -> anyhow::Result<(Vec<u8>, Transaction)> {
        let k256_priv_key =
            K256PrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();
        let new_address = k256_priv_key.to_address::<<DefaultContext as Spec>::Address>();

        let rule_enforcer_call_tx = RuleEnforcerCallMessage::ChangeAuthority::<DefaultContext> {
            new_authority: new_address,
        };

        let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
            soft_confirmation_rule_enforcer::SoftConfirmationRuleEnforcer<
                DefaultContext,
                <Da as DaService>::Spec,
            >,
        >>::encode_call(rule_enforcer_call_tx);

        let signed_blob = self.make_blob(raw_message.clone(), working_set, current_spec)?;

        let signed_tx = self.sign_tx(raw_message, working_set, current_spec)?;
        Ok((signed_blob, signed_tx))
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
