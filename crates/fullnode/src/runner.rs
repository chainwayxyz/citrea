use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use borsh::de::BorshDeserialize;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_primitives::{get_da_block_at_height, L1BlockCache, SyncError};
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sequencer_client::{GetSoftConfirmationResponse, SequencerClient};
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{
    BatchNumber, SlotNumber, StoredSoftConfirmation, StoredStateTransition,
};
use sov_modules_api::Context;
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaDataBatchProof, DaDataLightClient, DaSpec,
    SequencerCommitment,
};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::BatchReceipt;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use sov_stf_runner::{InitVariant, RollupPublicKeys, RpcConfig, RunnerConfig};
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<Stf, Sm, Da, Vm, C, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
    C: Context,
    DB: NodeLedgerOps,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: Stf,
    storage_manager: Sm,
    ledger_db: DB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    batch_hash: SoftConfirmationHash,
    rpc_config: RpcConfig,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    include_tx_body: bool,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    accept_public_input_as_proven: bool,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager,
    soft_confirmation_tx: broadcast::Sender<u64>,
}

impl<Stf, Sm, Da, Vm, C, DB> CitreaFullnode<Stf, Sm, Da, Vm, C, DB>
where
    Da: DaService<Error = anyhow::Error> + Send + Sync + 'static,
    Vm: ZkvmHost + Zkvm,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<
            Vm,
            Da::Spec,
            Condition = <Da::Spec as DaSpec>::ValidityCondition,
            PreState = Sm::NativeStorage,
            ChangeSet = Sm::NativeChangeSet,
        > + StfBlueprintTrait<C, Da::Spec, Vm>,
    C: Context,
    DB: NodeLedgerOps,
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
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
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

        let start_l2_height = ledger_db.get_next_items_numbers().soft_confirmation_number;

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            batch_hash: prev_batch_hash,
            rpc_config,
            sequencer_client: SequencerClient::new(runner_config.sequencer_client_url),
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            prover_da_pub_key: public_keys.prover_da_pub_key,
            phantom: std::marker::PhantomData,
            include_tx_body: runner_config.include_tx_body,
            code_commitments_by_spec,
            accept_public_input_as_proven: runner_config
                .accept_public_input_as_proven
                .unwrap_or(false),
            sync_blocks_count: runner_config.sync_blocks_count,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
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

        let middleware = tower::ServiceBuilder::new()
            .layer(citrea_common::rpc::get_cors_layer())
            .layer(citrea_common::rpc::get_healthcheck_proxy_layer());

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
    }

    async fn process_zk_proof(
        &self,
        l1_block: Da::FilteredBlock,
        proof: Proof,
    ) -> Result<(), SyncError> {
        tracing::info!(
            "Processing zk proof at height: {}",
            l1_block.header().height()
        );
        tracing::debug!("ZK proof: {:?}", proof);

        let state_transition =
            Vm::extract_output::<<Da as DaService>::Spec, Stf::StateRoot>(&proof)
                .expect("Proof should be deserializable");
        if state_transition.sequencer_da_public_key != self.sequencer_da_pub_key
            || state_transition.sequencer_public_key != self.sequencer_pub_key
        {
            return Err(anyhow!(
                "Proof verification: Sequencer public key or sequencer da public key mismatch. Skipping proof."
            ).into());
        }

        match &proof {
            Proof::Full(data) => {
                let code_commitment = self
                    .code_commitments_by_spec
                    .get(&state_transition.last_active_spec_id)
                    .expect("Proof public input must contain valid spec id");
                Vm::verify(data, code_commitment)
                    .map_err(|err| anyhow!("Failed to verify proof: {:?}. Skipping it...", err))?;
            }
            Proof::PublicInput(_) => {
                if !self.accept_public_input_as_proven {
                    return Err(anyhow!(
                        "Found public input in da block number: {}, Skipping to next proof..",
                        l1_block.header().height(),
                    )
                    .into());
                }
            }
        }

        let stored_state_transition = StoredStateTransition {
            initial_state_root: state_transition.initial_state_root.as_ref().to_vec(),
            final_state_root: state_transition.final_state_root.as_ref().to_vec(),
            state_diff: state_transition.state_diff,
            da_slot_hash: state_transition.da_slot_hash.clone().into(),
            sequencer_commitments_range: state_transition.sequencer_commitments_range,
            sequencer_public_key: state_transition.sequencer_public_key,
            sequencer_da_public_key: state_transition.sequencer_da_public_key,
            preproven_commitments: state_transition.preproven_commitments.clone(),
            validity_condition: borsh::to_vec(&state_transition.validity_condition).unwrap(),
        };

        let l1_hash = state_transition.da_slot_hash.into();

        // This is the l1 height where the sequencer commitment was read by the prover and proof generated by those commitments
        // We need to get commitments in this l1 height and set them as proven
        let l1_height = match self.ledger_db.get_l1_height_of_l1_hash(l1_hash)? {
            Some(l1_height) => l1_height,
            None => {
                return Err(anyhow!(
                    "Proof verification: L1 height not found for l1 hash: {:?}. Skipping proof.",
                    l1_hash
                )
                .into());
            }
        };

        let mut commitments_on_da_slot =
            match self.ledger_db.get_commitments_on_da_slot(l1_height)? {
                Some(commitments) => commitments,
                None => {
                    return Err(anyhow!(
                    "Proof verification: No commitments found for l1 height: {}. Skipping proof.",
                    l1_height
                )
                    .into());
                }
            };

        commitments_on_da_slot.sort_unstable();

        let excluded_commitment_indices = state_transition.preproven_commitments.clone();
        let filtered_commitments: Vec<SequencerCommitment> = commitments_on_da_slot
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !excluded_commitment_indices.contains(index))
            .map(|(_, commitment)| commitment.clone())
            .collect();

        let l2_height = filtered_commitments
            [state_transition.sequencer_commitments_range.0 as usize]
            .l2_start_block_number;
        // Fetch the block prior to the one at l2_height so compare state roots

        let prior_soft_confirmation_post_state_root = self
            .ledger_db
            .get_l2_state_root::<Stf::StateRoot>(l2_height - 1)?
            .ok_or_else(|| {
                anyhow!(
                "Proof verification: Could not find state root for L2 height: {}. Skipping proof.",
                l2_height - 1
            )
            })?;

        tracing::info!("out");

        if prior_soft_confirmation_post_state_root.as_ref()
            != state_transition.initial_state_root.as_ref()
        {
            return Err(anyhow!(
                    "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                    hex::encode(&prior_soft_confirmation_post_state_root),
                    hex::encode(&state_transition.initial_state_root)
                ).into());
        }

        for commitment in filtered_commitments
            .iter()
            .skip(state_transition.sequencer_commitments_range.0 as usize)
            .take(
                (state_transition.sequencer_commitments_range.1
                    - state_transition.sequencer_commitments_range.0
                    + 1) as usize,
            )
        {
            let l2_start_height = commitment.l2_start_block_number;
            let l2_end_height = commitment.l2_end_block_number;
            for i in l2_start_height..=l2_end_height {
                self.ledger_db
                    .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Proven)?;
            }
        }
        // store in ledger db
        self.ledger_db.update_verified_proof_data(
            l1_block.header().height(),
            proof.clone(),
            stored_state_transition,
        )?;
        Ok(())
    }

    async fn process_sequencer_commitment(
        &self,
        l1_block: &Da::FilteredBlock,
        sequencer_commitment: &SequencerCommitment,
    ) -> Result<(), SyncError> {
        let start_l2_height = sequencer_commitment.l2_start_block_number;
        let end_l2_height = sequencer_commitment.l2_end_block_number;

        tracing::info!(
            "Processing sequencer commitment. L2 Range = {}-{}.",
            start_l2_height,
            end_l2_height,
        );

        // Traverse each item's field of vector of transactions, put them in merkle tree
        // and compare the root with the one from the ledger
        let stored_soft_confirmations: Vec<StoredSoftConfirmation> =
            self.ledger_db.get_soft_confirmation_range(
                &(BatchNumber(start_l2_height)..BatchNumber(end_l2_height + 1)),
            )?;

        // Make sure that the number of stored soft confirmations is equal to the range's length.
        // Otherwise, if it is smaller, then we don't have some L2 blocks within the range
        // synced yet.
        if stored_soft_confirmations.len() < ((end_l2_height - start_l2_height) as usize) {
            return Err(SyncError::MissingL2(
                "L2 range not synced yet",
                start_l2_height,
                end_l2_height,
            ));
        }

        let soft_confirmations_tree = MerkleTree::<Sha256>::from_leaves(
            stored_soft_confirmations
                .iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        if soft_confirmations_tree.root() != Some(sequencer_commitment.merkle_root) {
            return Err(anyhow!(
                "Merkle root mismatch - expected 0x{} but got 0x{}. Skipping commitment.",
                hex::encode(
                    soft_confirmations_tree
                        .root()
                        .ok_or(anyhow!("Could not calculate soft confirmation tree root"))?
                ),
                hex::encode(sequencer_commitment.merkle_root)
            )
            .into());
        }

        self.ledger_db.update_commitments_on_da_slot(
            l1_block.header().height(),
            sequencer_commitment.clone(),
        )?;

        for i in start_l2_height..=end_l2_height {
            self.ledger_db
                .put_soft_confirmation_status(BatchNumber(i), SoftConfirmationStatus::Finalized)?;
        }
        self.ledger_db
            .set_last_commitment_l2_height(BatchNumber(end_l2_height))?;

        Ok(())
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

        let soft_confirmation_result = self.stf.apply_soft_confirmation(
            self.fork_manager.active_fork().spec_id,
            self.sequencer_pub_key.as_slice(),
            // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
            &self.state_root,
            pre_state,
            Default::default(),
            current_l1_block.header(),
            &current_l1_block.validity_condition(),
            &mut soft_confirmation.clone().into(),
        )?;

        let receipt = soft_confirmation_result.soft_confirmation_receipt;

        let next_state_root = soft_confirmation_result.state_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        self.storage_manager
            .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        self.ledger_db.commit_soft_confirmation(
            next_state_root.as_ref(),
            receipt,
            self.include_tx_body,
        )?;

        self.ledger_db.extend_l2_range_of_l1_slot(
            SlotNumber(current_l1_block.header().height()),
            BatchNumber(l2_height),
        )?;

        // Register this new block with the fork manager to active
        // the new fork on the next block.
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

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        // Last L1/L2 height before shutdown.
        let start_l1_height = {
            let last_scanned_l1_height = self
                .ledger_db
                .get_last_scanned_l1_height()
                .unwrap_or_else(|_| {
                    panic!("Failed to get last scanned l1 height from the ledger db")
                });

            match last_scanned_l1_height {
                Some(height) => height.0,
                None => get_initial_slot_height::<Da::Spec>(&self.sequencer_client).await,
            }
        };

        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = l1_sync(
            start_l1_height,
            self.da_service.clone(),
            l1_tx,
            self.l1_block_cache.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let (l2_tx, mut l2_rx) = mpsc::channel(1);
        let l2_sync_worker = sync_l2::<Da>(
            self.start_l2_height,
            self.sequencer_client.clone(),
            l2_tx,
            self.sync_blocks_count,
        );
        tokio::pin!(l2_sync_worker);

        let mut pending_l1_blocks: VecDeque<<Da as DaService>::FilteredBlock> =
            VecDeque::<Da::FilteredBlock>::new();
        let pending_l1 = &mut pending_l1_blocks;

        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        loop {
            select! {
                _ = &mut l1_sync_worker => {},
                _ = &mut l2_sync_worker => {},
                Some(l1_block) = l1_rx.recv() => {
                    pending_l1.push_back(l1_block);
                },
                _ = interval.tick() => {
                    self.process_l1_block(pending_l1).await
                },
                Some(l2_blocks) = l2_rx.recv() => {
                    for (l2_height, l2_block) in l2_blocks {
                        let l1_block = get_da_block_at_height(&self.da_service, l2_block.da_slot_height, self.l1_block_cache.clone()).await?;
                        if let Err(e) = self.process_l2_block(l2_height, l2_block, l1_block).await {
                            error!("Could not process L2 block: {}", e);
                        }
                    }
                },
            }
        }
    }

    pub async fn process_l1_block(
        &self,
        pending_l1_blocks: &mut VecDeque<<Da as DaService>::FilteredBlock>,
    ) {
        while !pending_l1_blocks.is_empty() {
            let l1_block = pending_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");
            // Set the l1 height of the l1 hash
            self.ledger_db
                .set_l1_height_of_l1_hash(
                    l1_block.header().hash().into(),
                    l1_block.header().height(),
                )
                .unwrap();

            let (sequencer_commitments, zk_proofs) =
                match self.extract_relevant_l1_data(l1_block.clone()).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Could not process L1 block: {}...skipping", e);
                        return;
                    }
                };

            for zk_proof in zk_proofs.clone().iter() {
                if let Err(e) = self
                    .process_zk_proof(l1_block.clone(), zk_proof.clone())
                    .await
                {
                    match e {
                        SyncError::MissingL2(msg, start_l2_height, end_l2_height) => {
                            warn!("Could not completely process ZK proofs. Missing L2 blocks {:?} - {:?}. msg = {}", start_l2_height, end_l2_height, msg);
                            return;
                        }
                        SyncError::Error(e) => {
                            error!("Could not process ZK proofs: {}...skipping", e);
                        }
                    }
                }
            }

            for sequencer_commitment in sequencer_commitments.clone().iter() {
                if let Err(e) = self
                    .process_sequencer_commitment(l1_block, sequencer_commitment)
                    .await
                {
                    match e {
                        SyncError::MissingL2(msg, start_l2_height, end_l2_height) => {
                            warn!("Could not completely process sequencer commitments. Missing L2 blocks {:?} - {:?}, msg = {}", start_l2_height, end_l2_height, msg);
                            return;
                        }
                        SyncError::Error(e) => {
                            error!("Could not process sequencer commitments: {}... skipping", e);
                        }
                    }
                }
            }

            // We do not care about the result of writing this height to the ledger db
            // So log and continue
            // Worst case scenario is that we will reprocess the same block after a restart
            let _ = self
                .ledger_db
                .set_last_scanned_l1_height(SlotNumber(l1_block.header().height()))
                .map_err(|e| {
                    error!("Could not set last scanned l1 height: {}", e);
                });

            pending_l1_blocks.pop_front();
        }
    }

    async fn extract_relevant_l1_data(
        &self,
        l1_block: Da::FilteredBlock,
    ) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<Proof>)> {
        let mut sequencer_commitments = Vec::<SequencerCommitment>::new();
        let mut zk_proofs = Vec::<Proof>::new();

        self.da_service
            .extract_relevant_proofs(&l1_block, &self.prover_da_pub_key)
            .await?
            .into_iter()
            .for_each(|data| match data {
                DaDataLightClient::ZKProof(proof) => {
                    zk_proofs.push(proof);
                }
            });

        self.da_service
            .extract_relevant_blobs(&l1_block)
            .into_iter()
            .for_each(|mut tx| {
                let data = DaDataBatchProof::try_from_slice(tx.full_data());
                // Check for commitment
                if tx.sender().as_ref() == self.sequencer_da_pub_key.as_slice() {
                    if let Ok(data) = data {
                        match data {
                            // TODO: This is where force transactions will land
                            DaDataBatchProof::SequencerCommitment(seq_com) => {
                                sequencer_commitments.push(seq_com);
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Found broken DA data in block 0x{}: {:?}",
                            hex::encode(l1_block.hash()),
                            data
                        );
                    }
                }
            });
        Ok((sequencer_commitments, zk_proofs))
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &Stf::StateRoot {
        &self.state_root
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
        let exponential_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .build();

        let inner_client = &sequencer_client;
        let soft_confirmations: Vec<GetSoftConfirmationResponse> =
            match retry_backoff(exponential_backoff.clone(), || async move {
                match inner_client
                    .get_soft_confirmation_range::<Da::Spec>(
                        l2_height..l2_height + sync_blocks_count,
                    )
                    .await
                {
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
            Ok(Some(soft_confirmation)) => return soft_confirmation.da_slot_height,
            _ => {
                // sleep 1
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}
