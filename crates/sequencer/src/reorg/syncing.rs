use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use std::vec;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::U256;
use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::utils::{compute_tx_hashes, compute_tx_merkle_root};
use citrea_common::{InitParams, RunnerConfig, SequencerConfig};
use citrea_evm::system_events::{create_system_transactions, SystemEvent};
use citrea_evm::{
    create_initial_system_events, populate_deposit_system_events, populate_set_block_info_event,
    AccountInfo, CallMessage, Evm, RlpEvmTransaction, MIN_TRANSACTION_GAS, SYSTEM_SIGNER,
};
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use jsonrpsee::core::client::{ClientT, Error as JsonrpseeError};
use jsonrpsee::http_client::HttpClientBuilder;
use reth_primitives::TransactionSignedEcRecovered;
use reth_transaction_pool::PoolTransaction;
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_api::default_signature::k256_private_key::K256PrivateKey;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{
    EncodeCall, L2Block, L2BlockModuleCallError, PrivateKey, SlotData, Spec, SpecId,
    StateValueAccessor, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::block::{L2Header, SignedL2Header};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::{L2BlockResult, StateTransitionError};
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use sov_state::ProverStorage;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use super::types::SoftConfirmationResponse;
use super::utils::collect_user_txs;

// This sequencer's purpose is to get all pre fork2 blocks including genesis and convert all of them to post fork2 blocks
// This sequencer will only run up to fork2 activation height, will not produce any blocks and will create the storage for the fork2 sequencer
pub struct CitreaReorgSequencer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    pub da_service: Arc<Da>,
    pub sov_tx_signer_priv_key: K256PrivateKey,
    pub ledger_db: DB,
    pub stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    pub storage_manager: ProverStorageManager,
    pub state_root: StorageRootHash,
    pub l2_block_hash: L2BlockHash,
    pub sequencer_config: SequencerConfig,
    pub runner_config: RunnerConfig,
}

impl<Da, DB> CitreaReorgSequencer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    pub fn new(
        init_params: InitParams,
        da_service: Arc<Da>,
        ledger_db: DB,
        sequencer_config: SequencerConfig,
        runner_config: RunnerConfig,
        stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
        storage_manager: ProverStorageManager,
    ) -> Self {
        let sov_tx_signer_priv_key = K256PrivateKey::try_from(
            hex::decode(&sequencer_config.private_key)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        Self {
            da_service,
            sov_tx_signer_priv_key,
            ledger_db,
            sequencer_config,
            runner_config,
            stf,
            storage_manager,
            state_root: init_params.prev_state_root,
            l2_block_hash: init_params.prev_l2_block_hash,
        }
    }
    pub async fn run(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), anyhow::Error> {
        let start_l2_height = self.ledger_db.get_head_l2_block_height()?.unwrap_or(0) + 1;
        let sequencer_client =
            HttpClientBuilder::default().build(&self.runner_config.sequencer_client_url)?;
        let last_processed_l1_height = 0;

        loop {
            let sequencer_client = &sequencer_client;
            let range = (
                start_l2_height,
                start_l2_height + self.runner_config.sync_blocks_count,
            );
            let exponential_backoff = ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_secs(1))
                .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
                .with_multiplier(1.5)
                .build();

            let soft_confirmation_responses = match retry_backoff(
                exponential_backoff,
                || async move {
                    let soft_confirmation_responses = sequencer_client
                        .request::<Vec<Option<SoftConfirmationResponse>>, _>(
                            "ledger_getSoftConfirmationRange",
                            [range.0, range.1],
                        )
                        .await;
                    match soft_confirmation_responses {
                        Ok(soft_confirmation_responses) => Ok(soft_confirmation_responses
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()),
                        Err(e) => match e {
                            JsonrpseeError::Transport(e) => {
                                let error_msg =
                                    format!("L2 Block: connection error during RPC call: {:?}", e);
                                debug!(error_msg);
                                Err(backoff::Error::Transient {
                                    err: error_msg,
                                    retry_after: None,
                                })
                            }
                            _ => Err(backoff::Error::Transient {
                                err: format!("L2 Block: unknown error from RPC call: {:?}", e),
                                retry_after: None,
                            }),
                        },
                    }
                },
            )
            .await
            {
                Ok(soft_confirmation_responses) => soft_confirmation_responses,
                Err(_) => {
                    panic!("Failed to get soft confirmation responses in reorg syncer with range: {:?}", range);
                }
            };

            for soft_confirmation_response in soft_confirmation_responses {
                // create new sys txs

                let pub_key = borsh::to_vec(&self.sov_tx_signer_priv_key.pub_key())?;

                let l2_block_info = HookL2BlockInfo {
                    l2_height: soft_confirmation_response.l2_height,
                    pre_state_root: self.state_root,
                    current_spec: SpecId::Fork2,
                    sequencer_pub_key: pub_key.clone(),
                    l1_fee_rate: soft_confirmation_response.l1_fee_rate,
                    timestamp: soft_confirmation_response.timestamp,
                };

                let prestate = self.storage_manager.create_storage_for_next_l2_height();

                let user_txs = collect_user_txs(&soft_confirmation_response);
                let deposit_data = soft_confirmation_response
                    .deposit_data
                    .iter()
                    .map(|d| d.tx.clone())
                    .collect::<Vec<_>>();
                let txs_to_run =
                    if soft_confirmation_response.da_slot_height > last_processed_l1_height {
                        let da_block = self
                            .da_service
                            .get_block_at(soft_confirmation_response.da_slot_height)
                            .await
                            .unwrap();
                        self.dry_run_transactions_post_fork2(
                            user_txs,
                            &pub_key,
                            prestate,
                            l2_block_info.clone(),
                            &deposit_data,
                            Some(da_block),
                        )
                        .unwrap()
                    } else {
                        self.dry_run_transactions_post_fork2(
                            user_txs,
                            &pub_key,
                            prestate,
                            l2_block_info.clone(),
                            &deposit_data,
                            None,
                        )
                        .unwrap()
                    };

                let prestate = self.storage_manager.create_storage_for_next_l2_height();
                assert_eq!(
                    prestate.version(),
                    soft_confirmation_response.l2_height,
                    "Prover storage version is corrupted"
                );

                let mut working_set = WorkingSet::new(prestate.clone());

                if let Err(err) =
                    self.stf
                        .begin_l2_block(&pub_key, &mut working_set, &l2_block_info)
                {
                    warn!(
                        "Failed to apply l2 block hook: {:?} \n reverting batch workspace",
                        err
                    );
                    bail!("Failed to apply begin l2 block hook: {:?}", err)
                }

                let mut blobs = vec![];
                let mut txs = vec![];

                // if a batch failed need to refetch nonce
                // so sticking to fetching from state makes sense
                let nonce = self.get_nonce(&mut working_set)?;

                let evm_txs_count = txs_to_run.len();
                if evm_txs_count > 0 {
                    let call_txs = CallMessage { txs: txs_to_run };
                    let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                        citrea_evm::Evm<DefaultContext>,
                    >>::encode_call(call_txs);

                    let signed_tx = self.sign_tx(raw_message, nonce)?;

                    blobs.push(signed_tx.to_blob()?);
                    txs.push(signed_tx);
                }

                self.stf
                    .apply_l2_block_txs(&l2_block_info, &txs, &mut working_set)
                    .expect("dry_run_transactions should have already checked this");

                self.stf.end_l2_block(l2_block_info, &mut working_set)?;

                // Finalize l2 block
                let l2_block_result =
                    self.stf
                        .finalize_l2_block(SpecId::Fork2, working_set, prestate);

                // Calculate tx hashes for merkle root
                let tx_hashes = compute_tx_hashes::<DefaultContext>(&txs, SpecId::Fork2);
                let tx_merkle_root = compute_tx_merkle_root(&tx_hashes)?;

                // create the l2 block header
                let header = L2Header::new(
                    soft_confirmation_response.l2_height,
                    self.l2_block_hash,
                    l2_block_result.state_root_transition.final_root,
                    soft_confirmation_response.l1_fee_rate,
                    tx_merkle_root,
                    soft_confirmation_response.timestamp,
                );

                let signed_header = self.sign_l2_block_header(header)?;
                // TODO: cleanup l2 block structure once we decide how to pull data from the running sequencer in the existing form
                let l2_block = L2Block::new(signed_header, txs.into());

                info!(
                    "Saving block #{}, Tx count: #{}",
                    l2_block.height(),
                    evm_txs_count
                );

                self.save_l2_block(l2_block, l2_block_result, tx_hashes, blobs)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn save_l2_block(
        &mut self,
        l2_block: L2Block<Transaction>,
        l2_block_result: L2BlockResult<ProverStorage, sov_state::Witness, sov_state::ReadWriteLog>,
        tx_hashes: Vec<[u8; 32]>,
        blobs: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        debug!(
            "Saving L2 block with hash: {:?} from sequencer {:?}",
            hex::encode(l2_block.hash()),
            hex::encode(l2_block.sequencer_pub_key()),
        );

        let state_root_transition = l2_block_result.state_root_transition;

        if state_root_transition.final_root.as_ref() == self.state_root.as_ref() {
            bail!("Max L2 blocks per L1 is reached for the current L1 block. State root is the same as before, skipping");
        }

        trace!(
            "State root after applying slot: {:?}",
            state_root_transition.final_root,
        );

        let next_state_root = state_root_transition.final_root;

        self.storage_manager
            .finalize_storage(l2_block_result.change_set);

        let l2_block_hash = l2_block.hash();

        self.ledger_db
            .commit_l2_block(l2_block, tx_hashes, Some(blobs))?;

        // TODO: https://github.com/chainwayxyz/citrea/issues/1992
        // // connect L1 and L2 height
        // self.ledger_db.extend_l2_range_of_l1_slot(
        //     SlotNumber(da_block.header().height()),
        //     L2BlockNumber(l2_height),
        // )?;

        self.state_root = next_state_root;
        self.l2_block_hash = l2_block_hash;

        // this was saving L2 block

        Ok(())
    }

    /// Fetches nonce from state
    pub(crate) fn get_nonce(
        &self,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
    ) -> anyhow::Result<u64> {
        let accounts = Accounts::<DefaultContext>::default();

        let pub_key = borsh::to_vec(&self.sov_tx_signer_priv_key.pub_key())?;

        match accounts
            .get_account(pub_key, working_set)
            .map_err(|e| anyhow!("Sequencer: Failed to get sov-account: {}", e))?
        {
            AccountExists { addr: _, nonce } => Ok(nonce),
            AccountEmpty => Ok(0),
        }
    }

    fn produce_and_run_system_transactions(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        evm: &Evm<DefaultContext>,
        working_set_to_discard: WorkingSet<<DefaultContext as Spec>::Storage>,
        deposit_data: &[Vec<u8>],
        da_block: Option<Da::FilteredBlock>,
        nonce: &mut u64,
    ) -> anyhow::Result<(
        Vec<RlpEvmTransaction>,
        WorkingSet<<DefaultContext as Spec>::Storage>,
    )> {
        let mut system_events = vec![];

        if let Some(l1_block) = da_block {
            // First l1 block of first l2 block
            if l2_block_info.l2_height() == 1 {
                let bridge_init_param =
                    hex::decode(self.sequencer_config.bridge_initialize_params.clone())
                        .expect("should deserialize");

                let initialize_events = create_initial_system_events(
                    l1_block.header().hash().into(),
                    l1_block.header().txs_commitment().into(),
                    l1_block.header().coinbase_txid_merkle_proof_height(),
                    l1_block.header().height(),
                    bridge_init_param,
                );
                // Initialize contracts
                system_events.extend(initialize_events);
                return self.process_sys_txs(
                    l2_block_info,
                    working_set_to_discard,
                    nonce,
                    evm,
                    system_events,
                );
            }

            let da_block_header = l1_block.header();
            let coinbase_depth = da_block_header.coinbase_txid_merkle_proof_height();

            let set_block_info_event = populate_set_block_info_event(
                da_block_header.hash().into(),
                da_block_header.txs_commitment().into(),
                coinbase_depth,
            );
            system_events.push(set_block_info_event);
        }

        let deposit_events = populate_deposit_system_events(deposit_data);

        system_events.extend(deposit_events);

        self.process_sys_txs(
            l2_block_info,
            working_set_to_discard,
            nonce,
            evm,
            system_events,
        )
    }

    pub(crate) fn sign_tx(&self, raw_message: Vec<u8>, nonce: u64) -> anyhow::Result<Transaction> {
        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        let tx = Transaction::new_signed_tx(
            &self.sov_tx_signer_priv_key.key_pair.to_bytes(),
            raw_message,
            0,
            nonce,
            true,
        );
        Ok(tx)
    }

    fn sign_l2_block_header(&mut self, header: L2Header) -> anyhow::Result<SignedL2Header> {
        let digest = header.compute_digest::<<DefaultContext as sov_modules_api::Spec>::Hasher>();
        let hash = Into::<[u8; 32]>::into(digest);

        let signature = self.sov_tx_signer_priv_key.sign(&hash);
        let pub_key = self.sov_tx_signer_priv_key.pub_key();
        let signature = borsh::to_vec(&signature)?;
        let pub_key = borsh::to_vec(&pub_key)?;
        Ok(SignedL2Header::new(header, hash, signature, pub_key))
    }

    fn process_sys_txs(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        mut working_set_to_discard: WorkingSet<<DefaultContext as Spec>::Storage>,
        nonce: &mut u64,
        evm: &Evm<DefaultContext>,
        system_events: Vec<SystemEvent>,
    ) -> anyhow::Result<(
        Vec<RlpEvmTransaction>,
        WorkingSet<<DefaultContext as Spec>::Storage>,
    )> {
        let mut all_txs = vec![];
        let system_signer = evm
            .account_info(&SYSTEM_SIGNER, &mut working_set_to_discard)
            .unwrap_or(AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: None,
            });

        let cfg = evm.cfg.get(&mut working_set_to_discard).unwrap();
        let chain_id = cfg.chain_id;

        let sys_txs = create_system_transactions(system_events, system_signer.nonce, chain_id);
        for sys_tx in sys_txs {
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

            let signed_tx = self.sign_tx(raw_message, *nonce)?;
            *nonce += 1;

            let txs = vec![signed_tx];

            let mut working_set = working_set_to_discard.checkpoint().to_revertable();

            if let Err(e) = self
                .stf
                .apply_l2_block_txs(l2_block_info, &txs, &mut working_set)
            {
                return Err(anyhow!("Failed to apply system transaction: {:?}", e));
            }
            working_set_to_discard = working_set.checkpoint().to_revertable();
            all_txs.push(sys_tx_rlp);
        }

        Ok((all_txs, working_set_to_discard))
    }

    fn dry_run_transactions_post_fork2(
        &mut self,
        user_transactions: Vec<TransactionSignedEcRecovered>,
        pub_key: &[u8],
        prestate: ProverStorage,
        l2_block_info: HookL2BlockInfo,
        deposit_data: &[Vec<u8>],
        da_block: Option<Da::FilteredBlock>,
    ) -> anyhow::Result<Vec<RlpEvmTransaction>> {
        let mut working_set_to_discard = WorkingSet::new(prestate.clone());
        let mut nonce = self.get_nonce(&mut working_set_to_discard)?;

        if let Err(err) =
            self.stf
                .begin_l2_block(pub_key, &mut working_set_to_discard, &l2_block_info)
        {
            warn!(
                "DryRun: Failed to apply l2 block hook: {:?} \n reverting batch workspace",
                err
            );
            bail!("DryRun: Failed to apply begin l2 block hook: {:?}", err)
        }

        let evm = citrea_evm::Evm::<DefaultContext>::default();
        // Initially fill with system transactions if any
        let (mut all_txs, mut working_set_to_discard) = self.produce_and_run_system_transactions(
            &l2_block_info,
            &evm,
            working_set_to_discard,
            deposit_data,
            da_block,
            &mut nonce,
        )?;

        for evm_tx in user_transactions {
            let mut buf = vec![];
            evm_tx.into_signed().encode_2718(&mut buf);
            let rlp_tx = RlpEvmTransaction { rlp: buf };
            let call_txs = CallMessage {
                txs: vec![rlp_tx.clone()],
            };
            let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                citrea_evm::Evm<DefaultContext>,
            >>::encode_call(call_txs);

            let signed_tx = self.sign_tx(raw_message, nonce)?;
            nonce += 1;

            let txs = vec![signed_tx];

            let mut working_set = working_set_to_discard.checkpoint().to_revertable();

            if let Err(e) = self
                .stf
                .apply_l2_block_txs(&l2_block_info, &txs, &mut working_set)
            {
                // Decrement nonce if the transaction failed
                nonce -= 1;
                let error_log_path = "error_log.txt";
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(error_log_path)?;

                let tx = TransactionSignedEcRecovered::try_from(rlp_tx.clone())
                    .expect("Should deserialize evm transaction");

                writeln!(file, "Error: {:?}, Transaction rlp: {:?}, tx signed ec recovered: {:?}, l2 block info: {:?}\n", e, rlp_tx, tx, l2_block_info)?;

                match e {
                    // Since this is the sequencer, it should never get a soft confirmation error or a hook error
                    StateTransitionError::L2BlockError(l2_block_error) => {
                        panic!("L2 block error: {:?}", l2_block_error)
                    }
                    StateTransitionError::HookError(soft_confirmation_hook_error) => {
                        panic!("Hook error: {:?}", soft_confirmation_hook_error)
                    }
                    StateTransitionError::ModuleCallError(soft_confirmation_module_call_error) => {
                        match soft_confirmation_module_call_error {
                            L2BlockModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                                cumulative_gas,
                                tx_gas_used: _,
                                block_gas_limit,
                            } => {
                                if block_gas_limit - cumulative_gas < MIN_TRANSACTION_GAS {
                                    break;
                                } else {
                                    working_set_to_discard = working_set.revert().to_revertable();
                                    continue;
                                }
                            }
                            L2BlockModuleCallError::EvmTxTypeNotSupported(_) => {
                                panic!("got unsupported tx type")
                            }
                            L2BlockModuleCallError::EvmTransactionExecutionError => {
                                working_set_to_discard = working_set.revert().to_revertable();
                                continue;
                            }
                            L2BlockModuleCallError::EvmMisplacedSystemTx => {
                                panic!("tried to execute system transaction")
                            }
                            L2BlockModuleCallError::EvmNotEnoughFundsForL1Fee => {
                                working_set_to_discard = working_set.revert().to_revertable();
                                continue;
                            }
                            L2BlockModuleCallError::EvmTxNotSerializable => {
                                panic!("Fed a non-serializable tx")
                            }
                            L2BlockModuleCallError::RuleEnforcerUnauthorized => unreachable!(),
                            L2BlockModuleCallError::ShortHeaderProofNotFound => unreachable!(),
                            L2BlockModuleCallError::ShortHeaderProofVerificationError => {
                                unreachable!()
                            }
                            L2BlockModuleCallError::EvmSystemTransactionPlacedAfterUserTx => {
                                panic!("System tx after user tx")
                            }
                            L2BlockModuleCallError::EvmSystemTxParseError => {
                                panic!("Sequencer produced incorrectly formatted system tx")
                            }
                            L2BlockModuleCallError::EvmSystemTxNotAllowedAfterFork2 => {
                                panic!("System tx not allowed after fork2")
                            }
                        }
                    }
                }
            };

            // if no errors
            // we can include the transaction in the block
            working_set_to_discard = working_set.checkpoint().to_revertable();
            all_txs.push(rlp_tx);
        }
        Ok(all_txs)
    }
}
