use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxHash, U256};
use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::backup::BackupManager;
use citrea_common::utils::{compute_tx_hashes, compute_tx_merkle_root};
use citrea_common::{InitParams, RollupPublicKeys, SequencerConfig};
use citrea_evm::system_events::create_system_transactions;
use citrea_evm::{
    get_last_l1_height_and_hash_in_light_client, populate_system_events, AccountInfo, CallMessage,
    RlpEvmTransaction, MIN_TRANSACTION_GAS, SYSTEM_SIGNER,
};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use parking_lot::Mutex;
use reth_execution_types::ChangedAccount;
use reth_primitives::TransactionSignedEcRecovered;
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
use sov_modules_api::hooks::{
    HookSoftConfirmationInfo, HookSoftConfirmationInfoV1, HookSoftConfirmationInfoV2,
};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    EncodeCall, L2Block, PrivateKey, SlotData, Spec, SpecId, StateDiff, StateValueAccessor,
    WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::soft_confirmation::{L2Header, SignedL2Header};
use sov_rollup_interface::stateful_statediff::StatefulStateDiff;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use sov_state::ProverStorage;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, instrument, trace, warn};
use tracing_subscriber::layer::SubscriberExt;

use crate::commitment::CommitmentService;
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::metrics::SEQUENCER_METRICS;
use crate::utils::recover_raw_transaction;

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
    storage_manager: ProverStorageManager,
    state_root: StorageRootHash,
    soft_confirmation_hash: SoftConfirmationHash,
    _sequencer_pub_key: Vec<u8>,
    _sequencer_k256_pub_key: Vec<u8>,
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
        storage_manager: ProverStorageManager,
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
            _sequencer_pub_key: public_keys.sequencer_public_key,
            _sequencer_k256_pub_key: public_keys.sequencer_k256_public_key,
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
        prestate: ProverStorage,
        da_block_header: <<Da as DaService>::Spec as DaSpec>::BlockHeader,
        soft_confirmation_info: HookSoftConfirmationInfo,
        deposit_data: &[Vec<u8>],
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        let start = Instant::now();

        let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);

        tracing::subscriber::with_default(silent_subscriber, || {
            let mut working_set_to_discard = WorkingSet::new(prestate.clone());

            let evm = citrea_evm::Evm::<DefaultContext>::default();
            if let Err(err) = self.stf.begin_soft_confirmation(
                pub_key,
                &mut working_set_to_discard,
                &da_block_header,
                &soft_confirmation_info,
            ) {
                warn!(
                "DryRun: Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                err
            );
                bail!(
                    "DryRun: Failed to apply begin soft confirmation hook: {:?}",
                    err
                )
            }

            let mut system_transactions = vec![];
            if soft_confirmation_info.current_spec() >= SpecId::Fork2 {
                // Read last l1 hash from bitcoin light client contract
                let mut l1_hash_in_contract = get_last_l1_height_and_hash_in_light_client(
                    &evm,
                    soft_confirmation_info.current_spec(),
                    &mut working_set_to_discard,
                )
                .1
                .map(Into::into);

                if soft_confirmation_info.l2_height() == 1 {
                    l1_hash_in_contract = None;
                }
                let bridge_init_param = hex::decode(self.config.bridge_initialize_params.clone())
                    .expect("should deserialize");
                let system_events = populate_system_events(
                    deposit_data,
                    da_block_header.hash().into(),
                    da_block_header.txs_commitment().into(),
                    da_block_header.height(),
                    l1_hash_in_contract,
                    bridge_init_param.as_slice(),
                );
                let system_signer = evm
                    .account_info(
                        &SYSTEM_SIGNER,
                        soft_confirmation_info.current_spec(),
                        &mut working_set_to_discard,
                    )
                    .unwrap_or(AccountInfo {
                        balance: U256::ZERO,
                        nonce: 0,
                        code_hash: None,
                    });
                let cfg = evm.cfg.get(&mut working_set_to_discard).unwrap();
                let chain_id = cfg.chain_id;
                system_transactions =
                    create_system_transactions(system_events, system_signer.nonce, chain_id);
            }
            let mut all_txs = vec![];

            // Initially process system txs if any
            // No need to check spec as they are only populated after fork2
            for sys_tx in system_transactions {
                let sys_tx = sys_tx.into_signed();

                // Cannot do into_ecrecovered here because we don't have a valid signature
                let sys_tx_ec_recovered =
                    TransactionSignedEcRecovered::from_signed_transaction(sys_tx, SYSTEM_SIGNER);

                let mut buf = vec![];
                sys_tx_ec_recovered.encode_2718(&mut buf);
                let sys_tx_rlp = RlpEvmTransaction { rlp: buf };

                let call_txs = CallMessage {
                    txs: vec![sys_tx_rlp.clone()],
                };
                let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                    citrea_evm::Evm<DefaultContext>,
                >>::encode_call(call_txs);

                let signed_tx = self.sign_tx(
                    raw_message,
                    &mut working_set_to_discard,
                    soft_confirmation_info.current_spec(),
                )?;

                let txs = vec![signed_tx];

                let mut working_set = working_set_to_discard.checkpoint().to_revertable();

                if let Err(e) = self.stf.apply_soft_confirmation_txs(
                    &soft_confirmation_info,
                    &txs,
                    &mut working_set,
                ) {
                    return Err(anyhow!("Failed to apply system transaction: {:?}", e));
                }

                working_set_to_discard = working_set.checkpoint().to_revertable();
                all_txs.push(sys_tx_rlp);
            }

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
                        let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                            citrea_evm::Evm<DefaultContext>,
                        >>::encode_call(call_txs);

                        let signed_tx = self.sign_tx(
                            raw_message,
                            &mut working_set_to_discard,
                            soft_confirmation_info.current_spec(),
                        )?;

                        let txs = vec![signed_tx];

                        let mut working_set = working_set_to_discard.checkpoint().to_revertable();

                        if let Err(e) = self.stf.apply_soft_confirmation_txs(
                            &soft_confirmation_info,
                            &txs,
                            &mut working_set,
                        ) {
                            match e {
                                        // Since this is the sequencer, it should never get a soft confirmation error or a hook error
                                        sov_rollup_interface::stf::StateTransitionError::SoftConfirmationError(soft_confirmation_error) => panic!("Soft confirmation error: {:?}", soft_confirmation_error),
                                        sov_rollup_interface::stf::StateTransitionError::HookError(soft_confirmation_hook_error) => panic!("Hook error: {:?}", soft_confirmation_hook_error),
                                        sov_rollup_interface::stf::StateTransitionError::ModuleCallError(soft_confirmation_module_call_error) => match soft_confirmation_module_call_error {
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
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTxTypeNotSupported(_) => panic!("got unsupported tx type"),
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTransactionExecutionError => {
                                                                                        invalid_senders.insert(evm_tx.transaction_id.sender);
                                                                                        working_set_to_discard = working_set.revert().to_revertable();
                                                                                        continue;
                                                                                    },
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmMisplacedSystemTx => panic!("tried to execute system transaction"),
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmNotEnoughFundsForL1Fee => {
                                                                                        l1_fee_failed_txs.push(*evm_tx.hash());
                                                                                        invalid_senders.insert(evm_tx.transaction_id.sender);
                                                                                        working_set_to_discard = working_set.revert().to_revertable();
                                                                                        continue;
                                                                                    },
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmTxNotSerializable => panic!("Fed a non-serializable tx"),
                                            sov_modules_api::SoftConfirmationModuleCallError::RuleEnforcerUnauthorized => unreachable!(),
                                            sov_modules_api::SoftConfirmationModuleCallError::ShortHeaderProofNotFound => unreachable!(),
                                            sov_modules_api::SoftConfirmationModuleCallError::ShortHeaderProofVerificationError => unreachable!(),
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmSystemTransactionPlacedAfterUserTx => panic!("System tx after user tx"),
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmSystemTxParseError => panic!("Sequencer produced incorrectly formatted system tx"),
                                                                                    },
                                    }
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
                L2BlockMode::Empty => Ok((all_txs, vec![])),
            }
        })
    }

    async fn produce_l2_block(
        &mut self,
        da_block: <Da as DaService>::FilteredBlock,
        l1_fee_rate: u128,
        l2_block_mode: L2BlockMode,
    ) -> anyhow::Result<(u64, u64, (StateDiff, StatefulStateDiff))> {
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

        // TODO: after L2Block refactor PR, we'll need to change native provider
        // Save short header proof to ledger db for Native Short Header Proof Provider Service
        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(da_block.clone());
        self.ledger_db
            .put_short_header_proof_by_l1_hash(
                &da_block.hash(),
                borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof to ledger db");

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

        let soft_confirmation_info = if active_fork_spec < SpecId::Fork2 {
            HookSoftConfirmationInfo::V1(HookSoftConfirmationInfoV1 {
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
            })
        } else {
            HookSoftConfirmationInfo::V2(HookSoftConfirmationInfoV2 {
                l2_height,
                pre_state_root: self.state_root,
                current_spec: active_fork_spec,
                pub_key: pub_key.clone(),
                l1_fee_rate,
                timestamp,
            })
        };

        let prestate = self.storage_manager.create_storage_for_next_l2_height();
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
                &deposit_data,
                l2_block_mode,
            )
            .await?;

        let prestate = self.storage_manager.create_storage_for_next_l2_height();
        assert_eq!(
            prestate.version(),
            l2_height,
            "Prover storage version is corrupted"
        );

        let mut working_set = WorkingSet::new(prestate.clone());

        // Execute the selected transactions
        if let Err(err) = self.stf.begin_soft_confirmation(
            &pub_key,
            &mut working_set,
            da_block.header(),
            &soft_confirmation_info,
        ) {
            warn!(
                "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                err
            );
            bail!("Failed to apply begin soft confirmation hook: {:?}", err)
        };

        let mut blobs = vec![];
        let mut txs = vec![];

        let evm_txs_count = txs_to_run.len();
        if evm_txs_count > 0 {
            let call_txs = CallMessage { txs: txs_to_run };
            let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                citrea_evm::Evm<DefaultContext>,
            >>::encode_call(call_txs);

            let signed_tx = self.sign_tx(
                raw_message,
                &mut working_set,
                soft_confirmation_info.current_spec(),
            )?;
            blobs.push(signed_tx.to_blob()?);
            txs.push(signed_tx);
        }

        // get the fork2 activation height
        // If next block activates Fork2 we should update rule enforcer authority
        // Because we use a new public key for sequencer now
        let next_fork = self.fork_manager.next_fork();
        if let Some(next_fork) = next_fork {
            if next_fork.spec_id == SpecId::Fork2
                && soft_confirmation_info.l2_height() + 1 == next_fork.activation_height
            {
                let (signed_blob, signed_tx) = self.update_sequencer_authority(&mut working_set, soft_confirmation_info.current_spec()).expect("Should create and sign soft confirmation rule enforcer authority change call messages");
                blobs.push(signed_blob);
                txs.push(signed_tx);
            }
        }

        self.stf
            .apply_soft_confirmation_txs(&soft_confirmation_info, &txs, &mut working_set)
            .expect("dry_run_transactions should have already checked this");

        self.stf
            .end_soft_confirmation(soft_confirmation_info, &mut working_set)?;

        // Finalize soft confirmation
        let soft_confirmation_result =
            self.stf
                .finalize_soft_confirmation(active_fork_spec, working_set, prestate);

        // Calculate tx hashes for merkle root
        let tx_hashes = compute_tx_hashes::<DefaultContext>(&txs, active_fork_spec);
        let tx_merkle_root = compute_tx_merkle_root(&tx_hashes)?;

        // create the soft confirmation header
        let header = L2Header::new(
            l2_height,
            da_block.header().txs_commitment().into(),
            self.soft_confirmation_hash,
            soft_confirmation_result.state_root_transition.final_root,
            l1_fee_rate,
            tx_merkle_root,
            timestamp,
        );

        let signed_header = self.sign_soft_confirmation(
            active_fork_spec,
            header,
            &blobs,
            deposit_data.clone(),
            da_block.header().height(),
            da_block.header().hash().into(),
        )?;
        let l2_block = L2Block::new(
            signed_header,
            txs.into(),
            deposit_data,
            da_block.header().height(),
            da_block.header().hash().into(),
        );

        debug!(
            "soft confirmation with hash: {:?} from sequencer {:?} has been successfully applied",
            hex::encode(l2_block.hash()),
            hex::encode(l2_block.sequencer_pub_key()),
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
            .finalize_storage(soft_confirmation_result.change_set);

        let soft_confirmation_hash = l2_block.hash();

        self.ledger_db
            .commit_l2_block(l2_block, tx_hashes, Some(blobs))?;

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

                            let _ = da_commitment_tx.send((l2_height, state_diff.0));
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

                            let _ = da_commitment_tx.send((l2_height, state_diff.0));
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

    fn sign_tx(
        &mut self,
        raw_message: Vec<u8>,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        spec_id: SpecId,
    ) -> anyhow::Result<Transaction> {
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
            spec_id >= SpecId::Fork2,
        );
        Ok(tx)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_soft_confirmation(
        &mut self,
        active_spec: SpecId,
        header: L2Header,
        blobs: &[Vec<u8>],
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> anyhow::Result<SignedL2Header> {
        match active_spec {
            SpecId::Genesis => self.sign_soft_confirmation_batch_v1(
                header,
                blobs,
                deposit_data,
                da_slot_height,
                da_slot_hash,
            ),
            SpecId::Kumquat => self.sign_soft_confirmation_batch_v2(
                header,
                blobs,
                deposit_data,
                da_slot_height,
                da_slot_hash,
            ),
            _ => self.sign_soft_confirmation_header(header),
        }
    }

    fn sign_soft_confirmation_header(
        &mut self,
        header: L2Header,
    ) -> anyhow::Result<SignedL2Header> {
        let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
        let hash = Into::<[u8; 32]>::into(digest);
        let priv_key = K256PrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();

        let signature = priv_key.sign(&hash);
        let pub_key = priv_key.pub_key();
        let signature = borsh::to_vec(&signature)?;
        let pub_key = borsh::to_vec(&pub_key)?;
        Ok(SignedL2Header::new(header, hash, signature, pub_key))
    }

    /// Signs necessary info and returns a BlockTemplate
    fn sign_soft_confirmation_batch_v2(
        &mut self,
        header: L2Header,
        blobs: &[Vec<u8>],
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> anyhow::Result<SignedL2Header> {
        let hash: [u8; 32] = header
            .hash_v2::<<DefaultContext as sov_modules_api::Spec>::Hasher>(
                da_slot_height,
                da_slot_hash,
                blobs.to_owned(),
                deposit_data,
            )
            .into();

        let priv_key = DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();

        let signature = priv_key.sign(&hash);
        let pub_key = priv_key.pub_key();
        let signature = borsh::to_vec(&signature)?;
        let pub_key = borsh::to_vec(&pub_key)?;
        Ok(SignedL2Header::new(header, hash, signature, pub_key))
    }

    /// Old version of sign_soft_confirmation_batch
    /// TODO: Remove derive(BorshSerialize) for UnsignedSoftConfirmation
    ///   when removing this fn
    /// FIXME: ^
    fn sign_soft_confirmation_batch_v1(
        &mut self,
        header: L2Header,
        blobs: &[Vec<u8>],
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> anyhow::Result<SignedL2Header> {
        let (hash, raw) = header
            .hash_v1::<<DefaultContext as sov_modules_api::Spec>::Hasher>(
                da_slot_height,
                da_slot_hash,
                blobs.to_owned(),
                deposit_data,
            )
            .map(|(hash, raw)| (Into::<[u8; 32]>::into(hash), raw))?;

        let priv_key = DefaultPrivateKey::try_from(self.sov_tx_signer_priv_key.as_slice()).unwrap();
        let signature = priv_key.sign(&raw);
        let pub_key = priv_key.pub_key();

        let signature = borsh::to_vec(&signature)?;
        let pub_key = borsh::to_vec(&pub_key)?;
        Ok(SignedL2Header::new(header, hash, signature, pub_key))
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

        let rule_enforcer_call_tx = RuleEnforcerCallMessage::ChangeAuthority {
            new_authority: new_address,
        };

        let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
            soft_confirmation_rule_enforcer::SoftConfirmationRuleEnforcer<
                DefaultContext,
                <Da as DaService>::Spec,
            >,
        >>::encode_call(rule_enforcer_call_tx);

        let signed_tx = self.sign_tx(raw_message, working_set, current_spec)?;
        let signed_blob = signed_tx.to_blob()?;

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
