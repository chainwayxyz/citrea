use core::panic;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use borsh::de::BorshDeserialize;
use citrea_primitives::fork::ForkManager;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_primitives::utils::merge_state_diffs;
use citrea_primitives::{get_da_block_at_height, L1BlockCache, MAX_STATEDIFF_SIZE_PROOF_THRESHOLD};
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use rand::Rng;
use sequencer_client::{GetSoftConfirmationResponse, SequencerClient};
use sov_db::ledger_db::ProverLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredStateTransition};
use sov_modules_api::storage::HierarchicalStorageManager;
use sov_modules_api::{BlobReaderTrait, Context, SignedSoftConfirmationBatch, SlotData, StateDiff};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Proof, StateTransitionData, ZkvmHost};
use sov_stf_runner::{
    InitVariant, ProverConfig, ProverService, RollupPublicKeys, RpcConfig, RunnerConfig,
};
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument, warn};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;

type CommitmentStateTransitionData<Stf, Vm, Da> = (
    VecDeque<Vec<<Stf as StateTransitionFunction<Vm, <Da as DaService>::Spec>>::Witness>>,
    VecDeque<Vec<SignedSoftConfirmationBatch>>,
    VecDeque<Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>>,
);

pub struct CitreaProver<C, Da, Sm, Vm, Stf, Ps, DB>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,

    Ps: ProverService<Vm>,
    DB: ProverLedgerOps + Clone,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: Stf,
    storage_manager: Sm,
    ledger_db: DB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    batch_hash: SoftConfirmationHash,
    rpc_config: RpcConfig,
    #[allow(dead_code)]
    prover_service: Option<Ps>,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    prover_config: Option<ProverConfig>,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager,
    soft_confirmation_tx: broadcast::Sender<u64>,
}

impl<C, Da, Sm, Vm, Stf, Ps, DB> CitreaProver<C, Da, Sm, Vm, Stf, Ps, DB>
where
    C: Context,
    Da: DaService<Error = anyhow::Error> + Send + Sync + 'static,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<
            Vm,
            Da::Spec,
            Condition = <Da::Spec as DaSpec>::ValidityCondition,
            PreState = Sm::NativeStorage,
            ChangeSet = Sm::NativeChangeSet,
        > + StfBlueprintTrait<C, Da::Spec, Vm>,
    Ps: ProverService<Vm, StateRoot = Stf::StateRoot, Witness = Stf::Witness, DaService = Da>,
    DB: ProverLedgerOps + Clone,
{
    /// Creates a new `StateTransitionRunner`.
    ///
    /// If a previous state root is provided, uses that as the starting point
    /// for execution. Otherwise, initializes the chain using the provided
    /// genesis config.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_config: RunnerConfig,
        public_keys: RollupPublicKeys,
        rpc_config: RpcConfig,
        da_service: Arc<Da>,
        ledger_db: DB,
        stf: Stf,
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        prover_service: Option<Ps>,
        prover_config: Option<ProverConfig>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        sync_blocks_count: u64,
        fork_manager: ForkManager,
        soft_confirmation_tx: broadcast::Sender<u64>,
    ) -> Result<Self, anyhow::Error> {
        let (prev_state_root, prev_batch_hash) = match init_variant {
            InitVariant::Initialized((state_root, batch_hash)) => {
                debug!("Chain is already initialized. Skipping initialization.");
                (state_root, batch_hash)
            }
            InitVariant::Genesis(params) => {
                info!("No history detected. Initializing chain...");
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

        // Start the main rollup loop
        let item_numbers = ledger_db.get_next_items_numbers();
        let last_soft_confirmation_processed_before_shutdown =
            item_numbers.soft_confirmation_number;
        // Last L1/L2 height before shutdown.
        let start_l2_height = last_soft_confirmation_processed_before_shutdown;

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            batch_hash: prev_batch_hash,
            rpc_config,
            prover_service,
            sequencer_client: SequencerClient::new(runner_config.sequencer_client_url),
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            phantom: std::marker::PhantomData,
            prover_config,
            code_commitments_by_spec,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            sync_blocks_count,
            fork_manager,
            soft_confirmation_tx,
        })
    }

    /// Starts a RPC server with provided rpc methods.
    pub async fn start_rpc_server(
        &self,
        methods: RpcModule<()>,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) {
        let bind_host = match self.rpc_config.bind_host.parse() {
            Ok(bind_host) => bind_host,
            Err(e) => {
                error!("Failed to parse bind host: {}", e);
                return;
            }
        };
        let listen_address = SocketAddr::new(bind_host, self.rpc_config.bind_port);

        let max_connections = self.rpc_config.max_connections;
        let max_subscriptions_per_connection = self.rpc_config.max_subscriptions_per_connection;
        let max_request_body_size = self.rpc_config.max_request_body_size;
        let max_response_body_size = self.rpc_config.max_response_body_size;
        let batch_requests_limit = self.rpc_config.batch_requests_limit;

        let _handle = tokio::spawn(async move {
            let server = ServerBuilder::default()
                .max_connections(max_connections)
                .max_subscriptions_per_connection(max_subscriptions_per_connection)
                .max_request_body_size(max_request_body_size)
                .max_response_body_size(max_response_body_size)
                .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
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
    }

    async fn check_and_recover_ongoing_proving_sessions(&self) -> Result<bool, anyhow::Error> {
        let prover_service = self
            .prover_service
            .as_ref()
            .expect("Prover service should be present");
        let results = prover_service
            .recover_proving_sessions_and_send_to_da(&self.da_service)
            .await?;
        if results.is_empty() {
            Ok(false)
        } else {
            for (tx_id, proof) in results {
                self.extract_and_store_proof(tx_id, proof).await?;
            }
            Ok(true)
        }
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let skip_submission_until_l1 = std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1")
            .map_or(0u64, |v| v.parse().unwrap_or(0));

        // Prover node should sync when a new sequencer commitment arrives
        // Check da block get and sync up to the latest block in the latest commitment
        let last_scanned_l1_height = self
            .ledger_db
            .get_last_scanned_l1_height()
            .unwrap_or_else(|_| panic!("Failed to get last scanned l1 height from the ledger db"));

        let start_l1_height = match last_scanned_l1_height {
            Some(height) => height.0,
            None => get_initial_slot_height::<Da::Spec>(&self.sequencer_client).await,
        };

        let prover_config = self.prover_config.clone().unwrap();

        // Create l1 sync worker task
        let (l1_tx, mut l1_rx) = mpsc::channel(1);

        let da_service = self.da_service.clone();
        let l1_block_cache = self.l1_block_cache.clone();

        let l1_handle = tokio::spawn(async move {
            l1_sync(start_l1_height, da_service, l1_tx, l1_block_cache).await;
        });
        tokio::pin!(l1_handle);

        // Create l2 sync worker task
        let (l2_tx, mut l2_rx) = mpsc::channel(1);

        let start_l2_height = self.start_l2_height;
        let sequencer_client = self.sequencer_client.clone();
        let sync_blocks_count = self.sync_blocks_count;

        let l2_handle = tokio::spawn(async move {
            sync_l2::<Da>(start_l2_height, sequencer_client, l2_tx, sync_blocks_count).await;
        });
        tokio::pin!(l2_handle);

        let da_service = self.da_service.clone();
        let l1_block_cache = self.l1_block_cache.clone();

        let mut pending_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock> =
            VecDeque::<Da::FilteredBlock>::new();
        let pending_l1 = &mut pending_l1_blocks;

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        loop {
            select! {
                _ = &mut l1_handle => {panic!("l1 sync handle exited unexpectedly");},
                _ = &mut l2_handle => {panic!("l2 sync handle exited unexpectedly");},
                Some(l1_block) = l1_rx.recv() => {
                    pending_l1.push_back(l1_block);
                 },
                _ = interval.tick() => {
                    if let Err(e) = self.process_l1_block(
                        pending_l1,
                        skip_submission_until_l1,
                        &prover_config,
                    ).await {
                        error!("Could not process L1 block and generate proof: {:?}", e);
                    }
                },
                Some(l2_blocks) = l2_rx.recv() => {
                    for (l2_height, l2_block) in l2_blocks {
                        let l1_block = get_da_block_at_height(&da_service, l2_block.da_slot_height, l1_block_cache.clone()).await?;
                        if let Err(e) = self.process_l2_block(l2_height, l2_block, l1_block).await {
                            error!("Could not process L2 block: {}", e);
                        }
                    }
                },
            }
        }
    }

    async fn process_l2_block(
        &mut self,
        l2_height: u64,
        soft_confirmation: GetSoftConfirmationResponse,
        current_l1_block: Da::FilteredBlock,
    ) -> anyhow::Result<()> {
        info!(
            "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
            l2_height,
            hex::encode(soft_confirmation.hash),
            current_l1_block.header().height()
        );

        if self.batch_hash != soft_confirmation.prev_hash {
            bail!("Previous hash mismatch at height: {}", l2_height);
        }

        let pre_state = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)?;

        let soft_confirmation_result = self
            .stf
            .apply_soft_confirmation(
                self.fork_manager.active_fork().spec_id,
                self.sequencer_pub_key.as_slice(),
                // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
                &self.state_root,
                pre_state,
                Default::default(),
                current_l1_block.header(),
                &current_l1_block.validity_condition(),
                &mut soft_confirmation.clone().into(),
            )
            .map_err(anyhow::Error::from)?;

        // TODO: maybe for prover we should accept this as valid and continue with proving
        let receipt = soft_confirmation_result.soft_confirmation_receipt;

        let next_state_root = soft_confirmation_result.state_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        // Save state diff to ledger DB
        self.ledger_db
            .set_l2_state_diff(BatchNumber(l2_height), soft_confirmation_result.state_diff)?;
        // Save witness data to ledger db
        self.ledger_db
            .set_l2_witness(l2_height, &soft_confirmation_result.witness)?;

        self.storage_manager
            .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        self.ledger_db
            .commit_soft_confirmation(next_state_root.as_ref(), receipt, true)?;

        self.ledger_db.extend_l2_range_of_l1_slot(
            SlotNumber(current_l1_block.header().height()),
            BatchNumber(l2_height),
        )?;

        // Register this new block with the fork manager to active
        // the new fork on the next block
        self.fork_manager.register_block(l2_height)?;

        // Only errors when there are no receivers
        let _ = self.soft_confirmation_tx.send(l2_height);

        self.state_root = next_state_root;
        self.batch_hash = soft_confirmation.hash;

        info!(
            "New State Root after soft confirmation #{} is: {:?}",
            l2_height, self.state_root
        );

        Ok(())
    }

    async fn process_l1_block(
        &mut self,
        pending_l1_blocks: &mut VecDeque<<Da as DaService>::FilteredBlock>,
        skip_submission_until_l1: u64,
        prover_config: &ProverConfig,
    ) -> Result<(), anyhow::Error> {
        let mut proving_session_exists = self.check_and_recover_ongoing_proving_sessions().await?;
        while !pending_l1_blocks.is_empty() {
            let l1_block = pending_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");
            // work on the first unprocessed l1 block
            let l1_height = l1_block.header().height();

            // Set the l1 height of the l1 hash
            self.ledger_db
                .set_l1_height_of_l1_hash(
                    l1_block.header().hash().into(),
                    l1_block.header().height(),
                )
                .unwrap();

            let mut da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction> =
                self.da_service.extract_relevant_blobs(l1_block);

            // if we don't do this, the zk circuit can't read the sequencer commitments
            da_data.iter_mut().for_each(|blob| {
                blob.full_data();
            });
            let mut sequencer_commitments: Vec<SequencerCommitment> =
                self.extract_sequencer_commitments(l1_block.header().hash().into(), &mut da_data);

            if sequencer_commitments.is_empty() {
                info!("No sequencer commitment found at height {}", l1_height,);
                self.ledger_db
                    .set_last_scanned_l1_height(SlotNumber(l1_height))
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put prover last scanned l1 height in the ledger db {}",
                            l1_height
                        )
                    });

                pending_l1_blocks.pop_front();
                continue;
            }

            info!(
                "Processing {} sequencer commitments at height {}",
                sequencer_commitments.len(),
                l1_block.header().height(),
            );

            // If the L2 range does not exist, we break off the local loop getting back to
            // the outer loop / select to make room for other tasks to run.
            // We retry the L1 block there as well.
            if !self.check_l2_range_exists(
                sequencer_commitments[0].l2_start_block_number,
                sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number,
            ) {
                break;
            }

            // if proof_sampling_number is 0, then we always prove and submit
            // otherwise we submit and prove with a probability of 1/proof_sampling_number
            let should_prove = prover_config.proof_sampling_number == 0
                || rand::thread_rng().gen_range(0..prover_config.proof_sampling_number) == 0;

            // Make sure all sequencer commitments are stored in ascending order.
            sequencer_commitments.sort_unstable();

            let (sequencer_commitments, preproven_commitments) =
                self.filter_out_proven_commitments(&sequencer_commitments)?;

            let da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader =
                l1_block.header().clone();

            let hash = da_block_header_of_commitments.hash();

            if !proving_session_exists && should_prove {
                let sequencer_commitments_groups =
                    self.break_sequencer_commitments_into_groups(sequencer_commitments)?;

                for sequencer_commitments in sequencer_commitments_groups {
                    // There is no ongoing bonsai session to recover
                    let transition_data: StateTransitionData<
                        Stf::StateRoot,
                        Stf::Witness,
                        Da::Spec,
                    > = self
                        .create_state_transition_data(
                            &sequencer_commitments,
                            &preproven_commitments,
                            da_block_header_of_commitments.clone(),
                            da_data.clone(),
                            l1_block,
                        )
                        .await?;

                    self.prove_state_transition(
                        transition_data,
                        skip_submission_until_l1,
                        l1_height,
                        hash.clone(),
                    )
                    .await?;
                    proving_session_exists = false;

                    self.save_commitments(sequencer_commitments, l1_height);
                }
            }

            if let Err(e) = self
                .ledger_db
                .set_last_scanned_l1_height(SlotNumber(l1_height))
            {
                panic!(
                    "Failed to put prover last scanned l1 height in the ledger db: {}",
                    e
                );
            }

            pending_l1_blocks.pop_front();
        }
        Ok(())
    }

    async fn prove_state_transition(
        &self,
        transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec>,
        skip_submission_until_l1: u64,
        l1_height: u64,
        hash: <<Da as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<(), anyhow::Error> {
        // Skip submission until l1 height
        if l1_height >= skip_submission_until_l1 {
            self.generate_and_submit_proof(transition_data, hash)
                .await?;
        } else {
            info!("Skipping proving for l1 height {}", l1_height);
        }
        Ok(())
    }

    async fn create_state_transition_data(
        &self,
        sequencer_commitments: &[SequencerCommitment],
        preproven_commitments: &[usize],
        da_block_header_of_commitments: <<Da as DaService>::Spec as DaSpec>::BlockHeader,
        da_data: Vec<<<Da as DaService>::Spec as DaSpec>::BlobTransaction>,
        l1_block: &Da::FilteredBlock,
    ) -> Result<StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec>, anyhow::Error> {
        let first_l2_height_of_l1 = sequencer_commitments[0].l2_start_block_number;
        let last_l2_height_of_l1 =
            sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number;
        let (
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ) = self
            .get_state_transition_data_from_commitments(sequencer_commitments, &self.da_service)
            .await?;
        let initial_state_root = self
            .ledger_db
            .get_l2_state_root::<Stf::StateRoot>(first_l2_height_of_l1 - 1)?
            .expect("There should be a state root");
        let initial_batch_hash = self
            .ledger_db
            .get_soft_confirmation_by_number(&BatchNumber(first_l2_height_of_l1))?
            .ok_or(anyhow!(
                "Could not find soft batch at height {}",
                first_l2_height_of_l1
            ))?
            .prev_hash;

        let final_state_root = self
            .ledger_db
            .get_l2_state_root::<Stf::StateRoot>(last_l2_height_of_l1)?
            .expect("There should be a state root");

        let (inclusion_proof, completeness_proof) = self
            .da_service
            .get_extraction_proof(l1_block, &da_data)
            .await;

        let transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec> =
            StateTransitionData {
                initial_state_root,
                final_state_root,
                initial_batch_hash,
                da_data,
                da_block_header_of_commitments,
                inclusion_proof,
                completeness_proof,
                soft_confirmations,
                state_transition_witnesses,
                da_block_headers_of_soft_confirmations,
                preproven_commitments: preproven_commitments.to_vec(),
                sequencer_commitments_range: (
                    0,
                    (sequencer_commitments.len() - 1)
                        .try_into()
                        .expect("cant be more than 4 billion commitments in a da block; qed"),
                ), // for now process all commitments
                sequencer_public_key: self.sequencer_pub_key.clone(),
                sequencer_da_public_key: self.sequencer_da_pub_key.clone(),
            };
        Ok(transition_data)
    }

    fn extract_sequencer_commitments(
        &self,
        l1_block_hash: [u8; 32],
        da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
    ) -> Vec<SequencerCommitment> {
        let mut sequencer_commitments = vec![];
        // if we don't do this, the zk circuit can't read the sequencer commitments
        da_data.iter_mut().for_each(|blob| {
            blob.full_data();
        });
        da_data.iter_mut().for_each(|tx| {
            let data = DaData::try_from_slice(tx.full_data());
            // Check for commitment
            if tx.sender().as_ref() == self.sequencer_da_pub_key.as_slice() {
                if let Ok(DaData::SequencerCommitment(seq_com)) = data {
                    sequencer_commitments.push(seq_com);
                } else {
                    tracing::warn!(
                        "Found broken DA data in block 0x{}: {:?}",
                        hex::encode(l1_block_hash),
                        data
                    );
                }
            }
        });
        sequencer_commitments
    }

    async fn get_state_transition_data_from_commitments(
        &self,
        sequencer_commitments: &[SequencerCommitment],
        da_service: &Arc<Da>,
    ) -> Result<CommitmentStateTransitionData<Stf, Vm, Da>, anyhow::Error> {
        let mut state_transition_witnesses: VecDeque<
            Vec<<Stf as StateTransitionFunction<Vm, <Da as DaService>::Spec>>::Witness>,
        > = VecDeque::new();
        let mut soft_confirmations: VecDeque<Vec<SignedSoftConfirmationBatch>> = VecDeque::new();
        let mut da_block_headers_of_soft_confirmations: VecDeque<
            Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>,
        > = VecDeque::new();
        for sequencer_commitment in sequencer_commitments.to_owned().iter() {
            // get the l2 height ranges of each seq_commitments
            let mut witnesses = vec![];
            let start_l2 = sequencer_commitment.l2_start_block_number;
            let end_l2 = sequencer_commitment.l2_end_block_number;
            let soft_confirmations_in_commitment = match self
                .ledger_db
                .get_soft_confirmation_range(&(BatchNumber(start_l2)..BatchNumber(end_l2 + 1)))
            {
                Ok(soft_confirmations) => soft_confirmations,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to get soft confirmations from the ledger db: {}",
                        e
                    ));
                }
            };
            let mut commitment_soft_confirmations = vec![];
            let mut da_block_headers_to_push: Vec<
                <<Da as DaService>::Spec as DaSpec>::BlockHeader,
            > = vec![];
            for soft_confirmation in soft_confirmations_in_commitment {
                if da_block_headers_to_push.is_empty()
                    || da_block_headers_to_push.last().unwrap().height()
                        != soft_confirmation.da_slot_height
                {
                    let filtered_block = match get_da_block_at_height(
                        da_service,
                        soft_confirmation.da_slot_height,
                        self.l1_block_cache.clone(),
                    )
                    .await
                    {
                        Ok(block) => block,
                        Err(_) => {
                            return Err(anyhow!(
                                "Error while fetching DA block at height: {}",
                                soft_confirmation.da_slot_height
                            ));
                        }
                    };
                    da_block_headers_to_push.push(filtered_block.header().clone());
                }
                let signed_soft_confirmation: SignedSoftConfirmationBatch =
                    soft_confirmation.clone().into();
                commitment_soft_confirmations.push(signed_soft_confirmation.clone());
            }
            soft_confirmations.push_back(commitment_soft_confirmations);

            da_block_headers_of_soft_confirmations.push_back(da_block_headers_to_push);
            for l2_height in sequencer_commitment.l2_start_block_number
                ..=sequencer_commitment.l2_end_block_number
            {
                let witness = match self.ledger_db.get_l2_witness::<Stf::Witness>(l2_height) {
                    Ok(witness) => witness,
                    Err(e) => {
                        return Err(anyhow!("Failed to get witness from the ledger db: {}", e))
                    }
                };

                witnesses.push(witness.expect("A witness must be present"));
            }
            state_transition_witnesses.push_back(witnesses);
        }
        Ok((
            state_transition_witnesses,
            soft_confirmations,
            da_block_headers_of_soft_confirmations,
        ))
    }

    fn check_l2_range_exists(&self, first_l2_height_of_l1: u64, last_l2_height_of_l1: u64) -> bool {
        let ledger_db = &self.ledger_db.clone();
        if let Ok(range) = ledger_db.clone().get_soft_confirmation_range(
            &(BatchNumber(first_l2_height_of_l1)..BatchNumber(last_l2_height_of_l1 + 1)),
        ) {
            if (range.len() as u64) >= (last_l2_height_of_l1 - first_l2_height_of_l1 + 1) {
                return true;
            }
        }
        false
    }

    async fn generate_and_submit_proof(
        &self,
        transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec>,
        hash: <<Da as DaService>::Spec as DaSpec>::SlotHash,
    ) -> Result<(), anyhow::Error> {
        let prover_service = self
            .prover_service
            .as_ref()
            .expect("Prover service should be present");

        prover_service.submit_witness(transition_data).await;

        prover_service.prove(hash.clone()).await?;

        let (tx_id, proof) = match prover_service
            .wait_for_proving_and_send_to_da(hash.clone(), &self.da_service)
            .await
        {
            Ok((tx_id, proof)) => (tx_id, proof),
            Err(e) => {
                return Err(anyhow!("Failed to prove and send to DA: {}", e));
            }
        };

        self.extract_and_store_proof(tx_id, proof).await
    }

    async fn extract_and_store_proof(
        &self,
        tx_id: <Da as DaService>::TransactionId,
        proof: Proof,
    ) -> Result<(), anyhow::Error> {
        let tx_id_u8 = tx_id.into();

        // l1_height => (tx_id, proof, transition_data)
        // save proof along with tx id to db, should be queriable by slot number or slot hash
        let transition_data = Vm::extract_output::<<Da as DaService>::Spec, Stf::StateRoot>(&proof)
            .expect("Proof should be deserializable");

        match &proof {
            Proof::PublicInput(_) => {
                warn!("Proof is public input, skipping");
            }
            Proof::Full(data) => {
                info!("Verifying proof!");
                let code_commitment = self
                    .code_commitments_by_spec
                    .get(&transition_data.last_active_spec_id)
                    .expect("Proof public input must contain valid spec id");
                Vm::verify(data, code_commitment)
                    .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;
            }
        }

        info!("transition data: {:?}", transition_data);

        let slot_hash = transition_data.da_slot_hash.into();

        let stored_state_transition = StoredStateTransition {
            initial_state_root: transition_data.initial_state_root.as_ref().to_vec(),
            final_state_root: transition_data.final_state_root.as_ref().to_vec(),
            state_diff: transition_data.state_diff,
            da_slot_hash: slot_hash,
            sequencer_commitments_range: transition_data.sequencer_commitments_range,
            sequencer_public_key: transition_data.sequencer_public_key,
            sequencer_da_public_key: transition_data.sequencer_da_public_key,
            validity_condition: borsh::to_vec(&transition_data.validity_condition).unwrap(),
        };
        let l1_height = self
            .ledger_db
            .get_l1_height_of_l1_hash(slot_hash)?
            .expect("l1 height should exist");

        if let Err(e) =
            self.ledger_db
                .put_proof_data(l1_height, tx_id_u8, proof, stored_state_transition)
        {
            panic!("Failed to put proof data in the ledger db: {}", e);
        }
        Ok(())
    }

    fn save_commitments(&self, sequencer_commitments: Vec<SequencerCommitment>, l1_height: u64) {
        for sequencer_commitment in sequencer_commitments.into_iter() {
            // Save commitments on prover ledger db
            self.ledger_db
                .update_commitments_on_da_slot(l1_height, sequencer_commitment.clone())
                .unwrap();

            let l2_start_height = sequencer_commitment.l2_start_block_number;
            let l2_end_height = sequencer_commitment.l2_end_block_number;
            for i in l2_start_height..=l2_end_height {
                self.ledger_db
                    .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Finalized)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put soft confirmation status in the ledger db {}",
                            i
                        )
                    });
            }
        }
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &Stf::StateRoot {
        &self.state_root
    }

    fn break_sequencer_commitments_into_groups(
        &self,
        sequencer_commitments: Vec<SequencerCommitment>,
    ) -> anyhow::Result<Vec<Vec<SequencerCommitment>>> {
        let mut result = vec![];

        let mut group = vec![];
        let mut cumulative_state_diff = StateDiff::new();
        for sequencer_commitment in sequencer_commitments {
            let mut sequencer_commitment_state_diff = StateDiff::new();
            for l2_height in sequencer_commitment.l2_start_block_number
                ..=sequencer_commitment.l2_end_block_number
            {
                let state_diff = self
                    .ledger_db
                    .get_l2_state_diff(BatchNumber(l2_height))?
                    .ok_or(anyhow!(
                        "Could not find state diff for L2 range {}-{}",
                        sequencer_commitment.l2_start_block_number,
                        sequencer_commitment.l2_end_block_number
                    ))?;
                sequencer_commitment_state_diff =
                    merge_state_diffs(sequencer_commitment_state_diff, state_diff);
            }
            cumulative_state_diff = merge_state_diffs(
                cumulative_state_diff,
                sequencer_commitment_state_diff.clone(),
            );

            let serialized_state_diff = borsh::to_vec(&cumulative_state_diff)?;

            let state_diff_threshold_reached =
                serialized_state_diff.len() as u64 > MAX_STATEDIFF_SIZE_PROOF_THRESHOLD;

            if state_diff_threshold_reached && !group.is_empty() {
                // We've exceeded the limit with the current commitments
                // so we have to stop at the previous one.
                result.push(group);
                // Reset the cumulative state diff to be equal to the current commitment state diff
                cumulative_state_diff = sequencer_commitment_state_diff;
                group = vec![sequencer_commitment.clone()];
            } else {
                group.push(sequencer_commitment.clone());
            }
        }

        // If the last group hasn't been reset because it has not reached the threshold,
        // Add it anyway
        if !group.is_empty() {
            result.push(group);
        }

        Ok(result)
    }

    /// Remove proven commitments using the end block number of the L2 range.
    /// This is basically filtering out finalized soft confirmations.
    fn filter_out_proven_commitments(
        &self,
        sequencer_commitments: &[SequencerCommitment],
    ) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
        let mut preproven_commitments = vec![];
        let mut filtered = vec![];
        let mut visited_l2_ranges = HashSet::new();
        for (index, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
            // Handle commitments which have the same L2 range
            let current_range = (
                sequencer_commitment.l2_start_block_number,
                sequencer_commitment.l2_end_block_number,
            );
            if visited_l2_ranges.contains(&current_range) {
                continue;
            }
            visited_l2_ranges.insert(current_range);

            // Check if the commitment was previously finalized.
            let Some(status) = self.ledger_db.get_soft_confirmation_status(BatchNumber(
                sequencer_commitment.l2_end_block_number,
            ))?
            else {
                filtered.push(sequencer_commitment.clone());
                continue;
            };

            if status != SoftConfirmationStatus::Finalized {
                filtered.push(sequencer_commitment.clone());
            } else {
                preproven_commitments.push(index);
            }
        }

        Ok((filtered, preproven_commitments))
    }
}

async fn l1_sync<Da>(
    start_l1_height: u64,
    da_service: Arc<Da>,
    sender: mpsc::Sender<Da::FilteredBlock>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
) where
    Da: DaService,
{
    let mut l1_height = start_l1_height;
    info!("Starting to sync from L1 height {}", l1_height);

    'block_sync: loop {
        // TODO: for a node, the da block at slot_height might not have been finalized yet
        // should wait for it to be finalized
        let last_finalized_l1_block_header =
            match da_service.get_last_finalized_block_header().await {
                Ok(header) => header,
                Err(e) => {
                    error!("Could not fetch last finalized L1 block header: {}", e);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

        let new_l1_height = last_finalized_l1_block_header.height();

        for block_number in l1_height + 1..=new_l1_height {
            let l1_block =
                match get_da_block_at_height(&da_service, block_number, l1_block_cache.clone())
                    .await
                {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Could not fetch last finalized L1 block: {}", e);
                        sleep(Duration::from_secs(2)).await;
                        continue 'block_sync;
                    }
                };
            if block_number > l1_height {
                l1_height = block_number;
                if let Err(e) = sender.send(l1_block).await {
                    error!("Could not notify about L1 block: {}", e);
                    continue 'block_sync;
                }
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn sync_l2<Da>(
    start_l2_height: u64,
    sequencer_client: SequencerClient,
    sender: mpsc::Sender<Vec<(u64, GetSoftConfirmationResponse)>>,
    sync_blocks_count: u64,
) where
    Da: DaService,
{
    let mut l2_height = start_l2_height;
    info!("Starting to sync from L2 height {}", l2_height);
    loop {
        let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .with_multiplier(1.0)
            .build();

        let inner_client = &sequencer_client;
        let soft_confirmations: Vec<GetSoftConfirmationResponse> =
            match retry_backoff(exponential_backoff.clone(), || async move {
                let soft_confirmations = inner_client
                    .get_soft_confirmation_range::<Da::Spec>(
                        l2_height..l2_height + sync_blocks_count,
                    )
                    .await;

                match soft_confirmations {
                    Ok(soft_confirmations) => {
                        Ok(soft_confirmations.into_iter().flatten().collect::<Vec<_>>())
                    }
                    Err(e) => match e.downcast_ref::<JsonrpseeError>() {
                        Some(JsonrpseeError::Transport(e)) => {
                            let error_msg = format!(
                                "Soft Confirmation: connection error during RPC call: {:?}",
                                e
                            );
                            debug!(error_msg);
                            Err(backoff::Error::Transient {
                                err: error_msg,
                                retry_after: None,
                            })
                        }
                        _ => Err(backoff::Error::Transient {
                            err: format!("Soft Confirmation: unknown error from RPC call: {:?}", e),
                            retry_after: None,
                        }),
                    },
                }
            })
            .await
            {
                Ok(soft_confirmations) => soft_confirmations,
                Err(_) => {
                    continue;
                }
            };

        if soft_confirmations.is_empty() {
            debug!(
                "Soft Confirmation: no batch at starting height {}, retrying...",
                l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let soft_confirmations: Vec<(u64, GetSoftConfirmationResponse)> = (l2_height
            ..l2_height + soft_confirmations.len() as u64)
            .zip(soft_confirmations)
            .collect();

        l2_height += soft_confirmations.len() as u64;

        if let Err(e) = sender.send(soft_confirmations).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}

async fn get_initial_slot_height<Da: DaSpec>(client: &SequencerClient) -> u64 {
    loop {
        match client.get_soft_confirmation::<Da>(1).await {
            Ok(Some(batch)) => return batch.da_slot_height,
            _ => {
                // sleep 1
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}
