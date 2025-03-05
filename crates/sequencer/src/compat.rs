use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use std::vec;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::TxHash;
use anyhow::{anyhow, bail};
use citrea_common::utils::{compute_tx_hashes, compute_tx_merkle_root};
use citrea_evm::{CallMessage, RlpEvmTransaction, MIN_TRANSACTION_GAS};
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use reth_transaction_pool::{BestTransactions, EthPooledTransaction, ValidPoolTransaction};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_api::default_signature::k256_private_key::K256PrivateKey;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_api::hooks::{HookSoftConfirmationInfo, HookSoftConfirmationInfoV1};
use sov_modules_api::{EncodeCall, L2Block, PrivateKey, SlotData, SpecId, StateDiff, WorkingSet};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::soft_confirmation::L2Header;
use sov_state::storage::NativeStorage;
use sov_state::ProverStorage;
use tracing::level_filters::LevelFilter;
use tracing::{debug, info, warn};
use tracing_subscriber::layer::SubscriberExt;

use crate::metrics::SEQUENCER_METRICS;
use crate::runner::L2BlockMode;
use crate::CitreaSequencer;

impl<Da, DB> CitreaSequencer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Sync + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    async fn dry_run_transactions_pre_fork2(
        &mut self,
        mut transactions: Box<
            dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>,
        >,
        pub_key: &[u8],
        prestate: ProverStorage,
        soft_confirmation_info: HookSoftConfirmationInfo,
        l2_block_mode: &L2BlockMode,
        da_block: Da::FilteredBlock,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        let start = Instant::now();

        let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);

        tracing::subscriber::with_default(silent_subscriber, || {
            let mut working_set_to_discard = WorkingSet::new(prestate.clone());

            let mut nonce = self.get_nonce(
                &mut working_set_to_discard,
                soft_confirmation_info.current_spec(),
            )?;

            if let Err(err) = self.stf.begin_soft_confirmation_pre_fork2(
                pub_key,
                &mut working_set_to_discard,
                da_block.header(),
                &soft_confirmation_info,
            ) {
                warn!(
                    "Failed to apply soft confirmation hook: {:?} \n reverting batch workspace",
                    err
                );
                bail!("Failed to apply begin soft confirmation hook: {:?}", err)
            };

            let mut all_txs = vec![];

            match l2_block_mode {
                L2BlockMode::NotEmpty => {
                    // TODO: Below can be common fn
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
                            soft_confirmation_info.current_spec(),
                            nonce,
                        )?;
                        nonce += 1;

                        let txs = vec![signed_tx];

                        let mut working_set = working_set_to_discard.checkpoint().to_revertable();

                        if let Err(e) = self.stf.apply_soft_confirmation_txs(
                            &soft_confirmation_info,
                            &txs,
                            &mut working_set,
                        ) {
                            // Decrement nonce if the transaction failed
                            nonce -= 1;
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
                                            sov_modules_api::SoftConfirmationModuleCallError::EvmSystemTxNotAllowedAfterFork2 => panic!("Evm System Tx Not Allowed After Fork2"),
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

    pub(crate) async fn produce_l2_block_pre_fork2(
        &mut self,
        da_block: Da::FilteredBlock,
        l1_fee_rate: u128,
        l2_block_mode: &L2BlockMode,
    ) -> anyhow::Result<(u64, u64, StateDiff)> {
        let active_fork_spec = self.fork_manager.active_fork().spec_id;

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

        debug!(
            "Applying soft confirmation on DA block: {}",
            hex::encode(da_block.header().hash().into())
        );
        let soft_confirmation_info = HookSoftConfirmationInfo::V1(HookSoftConfirmationInfoV1 {
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
        });

        let prestate = self.storage_manager.create_storage_for_next_l2_height();

        let evm_txs = self.get_best_transactions()?;
        let da_block_height = da_block.header().height();

        // Dry running transactions would basically allow for figuring out a list of
        // all transactions that would fit into the current block and the list of transactions
        // which do not have enough balance to pay for the L1 fee.
        let (txs_to_run, l1_fee_failed_txs) = self
            .dry_run_transactions_pre_fork2(
                evm_txs,
                &pub_key,
                prestate.clone(),
                soft_confirmation_info.clone(),
                l2_block_mode,
                da_block.clone(),
            )
            .await?;

        let prestate = self.storage_manager.create_storage_for_next_l2_height();
        assert_eq!(
            prestate.version(),
            l2_height,
            "Prover storage version is corrupted"
        );

        let mut working_set = WorkingSet::new(prestate.clone());

        let da_header = da_block.header();
        if let Err(err) = self.stf.begin_soft_confirmation_pre_fork2(
            &pub_key,
            &mut working_set,
            da_header,
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

        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let mut nonce = self.get_nonce(&mut working_set, soft_confirmation_info.current_spec())?;

        let evm_txs_count = txs_to_run.len();
        if evm_txs_count > 0 {
            let call_txs = CallMessage { txs: txs_to_run };
            let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                citrea_evm::Evm<DefaultContext>,
            >>::encode_call(call_txs);

            let signed_tx =
                self.sign_tx(raw_message, soft_confirmation_info.current_spec(), nonce)?;
            // Increment nonce after sov tx for other possible sov txs
            nonce += 1;

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
                let (signed_blob, signed_tx) = self.update_sequencer_authority( soft_confirmation_info.current_spec(), nonce).expect("Should create and sign soft confirmation rule enforcer authority change call messages");
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
            self.soft_confirmation_hash,
            soft_confirmation_result.state_root_transition.final_root,
            l1_fee_rate,
            tx_merkle_root,
            timestamp,
        );

        let da_header = da_block.header().clone();
        let signed_header = self.sign_soft_confirmation(
            active_fork_spec,
            header,
            &blobs,
            deposit_data.clone(),
            Some(da_header.height()),
            Some(da_header.hash().into()),
            Some(da_header.txs_commitment().into()),
        )?;
        let l2_block = L2Block::new(
            signed_header,
            txs.into(),
            deposit_data,
            da_header.height(),
            da_header.hash().into(),
            da_header.txs_commitment().into(),
        );

        info!(
            "Saving block #{}, Tx count: #{}",
            l2_block.l2_height(),
            evm_txs_count
        );

        let state_diff =
            self.save_l2_block(l2_block, soft_confirmation_result, tx_hashes, blobs)?;

        self.maintain_mempool(l1_fee_failed_txs)?;

        Ok((l2_height, da_block_height, state_diff))
    }
}
