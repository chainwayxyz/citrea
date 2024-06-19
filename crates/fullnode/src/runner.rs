use std::marker::PhantomData;
use std::net::SocketAddr;

use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use borsh::de::BorshDeserialize;
use borsh::BorshSerialize as _;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::RpcModule;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sequencer_client::{GetSoftBatchResponse, SequencerClient};
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredSoftBatch, StoredStateTransition};
use sov_modules_api::Context;
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaData, DaSpec, SequencerCommitment,
};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
pub use sov_rollup_interface::stf::BatchReceipt;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use sov_stf_runner::{InitVariant, RollupPublicKeys, RpcConfig, RunnerConfig};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<Stf, Sm, Da, Vm, C>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
    C: Context,
{
    start_l2_height: u64,
    start_l1_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    /// made pub so that sequencer can clone it
    pub ledger_db: LedgerDB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    rpc_config: RpcConfig,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    include_tx_body: bool,
    code_commitment: Vm::CodeCommitment,
    accept_public_input_as_proven: bool,
}

impl<Stf, Sm, Da, Vm, C> CitreaFullnode<Stf, Sm, Da, Vm, C>
where
    Da: DaService<Error = anyhow::Error> + Clone + Send + Sync + 'static,
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
        da_service: Da,
        ledger_db: LedgerDB,
        stf: Stf,
        mut storage_manager: Sm,
        init_variant: InitVariant<Stf, Vm, Da::Spec>,
        code_commitment: Vm::CodeCommitment,
    ) -> Result<Self, anyhow::Error> {
        let prev_state_root = match init_variant {
            InitVariant::Initialized(state_root) => {
                debug!("Chain is already initialized. Skipping initialization.");
                state_root
            }
            InitVariant::Genesis(params) => {
                info!("No history detected. Initializing chain...");
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

        // Start the main rollup loop
        let item_numbers = ledger_db.get_next_items_numbers();

        // Last L1/L2 height before shutdown.
        let start_l1_height = item_numbers.slot_number;
        let start_l2_height = item_numbers.soft_batch_number;

        Ok(Self {
            start_l1_height,
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            rpc_config,
            sequencer_client: SequencerClient::new(runner_config.sequencer_client_url),
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            prover_da_pub_key: public_keys.prover_da_pub_key,
            phantom: std::marker::PhantomData,
            include_tx_body: runner_config.include_tx_body,
            code_commitment,
            accept_public_input_as_proven: runner_config
                .accept_public_input_as_proven
                .unwrap_or(false),
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
    }

    async fn process_zk_proofs(
        &self,
        l1_block: Da::FilteredBlock,
        zk_proofs: Vec<Proof>,
    ) -> anyhow::Result<()> {
        for proof in zk_proofs {
            tracing::warn!("Processing zk proof: {:?}", proof);
            let state_transition = match proof.clone() {
                Proof::Full(proof) => {
                    let code_commitment = self.code_commitment.clone();

                    tracing::warn!(
                        "using code commitment: {:?}",
                        serde_json::to_string(&code_commitment).unwrap()
                    );

                    if let Ok(proof_data) = Vm::verify_and_extract_output::<
                        <Da as DaService>::Spec,
                        Stf::StateRoot,
                    >(&proof, &code_commitment)
                    {
                        if proof_data.sequencer_da_public_key != self.sequencer_da_pub_key
                            || proof_data.sequencer_public_key != self.sequencer_pub_key
                        {
                            tracing::warn!(
                                "Proof verification: Sequencer public key or sequencer da public key mismatch. Skipping proof."
                            );
                            continue;
                        }
                        proof_data
                    } else {
                        tracing::warn!(
                            "Proof verification: SNARK verification failed. Skipping to next proof.."
                        );
                        continue;
                    }
                }
                Proof::PublicInput(_) => {
                    if !self.accept_public_input_as_proven {
                        tracing::warn!(
                            "Found public input in da block number: {:?}, Skipping to next proof..",
                            l1_block.header().height(),
                        );
                        continue;
                    }
                    // public input is accepted only in tests, so ok to expect
                    Vm::extract_output(&proof).expect("Proof should be deserializable")
                }
            };

            let stored_state_transition = StoredStateTransition {
                initial_state_root: state_transition.initial_state_root.as_ref().to_vec(),
                final_state_root: state_transition.final_state_root.as_ref().to_vec(),
                state_diff: state_transition.state_diff,
                da_slot_hash: state_transition.da_slot_hash.clone().into(),
                sequencer_public_key: state_transition.sequencer_public_key,
                sequencer_da_public_key: state_transition.sequencer_da_public_key,
                validity_condition: state_transition.validity_condition.try_to_vec().unwrap(),
            };

            let l1_hash = state_transition.da_slot_hash.into();

            // This is the l1 height where the sequencer commitment was read by the prover and proof generated by those commitments
            // We need to get commitments in this l1 height and set them as proven
            let l1_height = match self.ledger_db.get_l1_height_of_l1_hash(l1_hash)? {
                Some(l1_height) => l1_height,
                None => {
                    tracing::warn!(
                        "Proof verification: L1 height not found for l1 hash: {:?}. Skipping proof.",
                        l1_hash
                    );
                    continue;
                }
            };

            // TODO: Handle error
            let proven_commitments = match self.ledger_db.get_commitments_on_da_slot(l1_height)? {
                Some(commitments) => commitments,
                None => {
                    tracing::warn!(
                        "Proof verification: No commitments found for l1 height: {}. Skipping proof.",
                        l1_height
                    );
                    continue;
                }
            };

            let first_slot_hash = proven_commitments[0].l1_start_block_hash;
            let l1_height_start = match self.ledger_db.get_l1_height_of_l1_hash(first_slot_hash)? {
                Some(l1_height) => l1_height,
                None => {
                    tracing::error!(
                        "Proof verification: For a known and verified sequencer commitment, L1 height not found for l1 hash: {:?}. Skipping proof.",
                        l1_hash
                    );
                    continue;
                }
            };
            match self
                .ledger_db
                .get_l2_range_by_l1_height(SlotNumber(l1_height_start))?
            {
                Some((start, _)) => {
                    let l2_height = start.0;
                    let soft_batches = self.ledger_db.get_soft_batch_range(
                        &(BatchNumber(l2_height)..BatchNumber(l2_height + 1)),
                    )?;

                    let soft_batch = soft_batches.first().unwrap();
                    if soft_batch.pre_state_root.as_slice()
                        != state_transition.initial_state_root.as_ref()
                    {
                        tracing::warn!(
                            "Proof verification: For a known and verified sequencer commitment. Pre state root mismatch - expected 0x{} but got 0x{}. Skipping proof.",
                            hex::encode(&soft_batch.pre_state_root),
                            hex::encode(&state_transition.initial_state_root)
                        );
                        continue;
                    }
                }
                None => {
                    tracing::warn!(
                        "Proof verification: For a known and verified sequencer commitment, L1 L2 connection does not exist. L1 height = {}. Skipping proof.",
                        l1_height_start
                    );
                    continue;
                }
            }

            for commitment in proven_commitments {
                let l1_height_start = match self
                    .ledger_db
                    .get_l1_height_of_l1_hash(commitment.l1_start_block_hash)?
                {
                    Some(l1_height) => l1_height,
                    None => {
                        tracing::warn!("Proof verification: For a known and verified sequencer commitment, L1 height not found for l1 hash: {:?}", l1_hash);
                        continue;
                    }
                };

                let l1_height_end = match self
                    .ledger_db
                    .get_l1_height_of_l1_hash(commitment.l1_end_block_hash)?
                {
                    Some(l1_height) => l1_height,
                    None => {
                        tracing::warn!("Proof verification: For a known and verified sequencer commitment, L1 height not found for l1 hash: {:?}", l1_hash);
                        continue;
                    }
                };

                // All soft confirmations in these blocks are now proven
                for i in l1_height_start..=l1_height_end {
                    self.ledger_db.put_soft_confirmation_status(
                        SlotNumber(i),
                        SoftConfirmationStatus::Proven,
                    )?;
                }
            }
            // store in ledger db
            self.ledger_db.update_verified_proof_data(
                l1_block.header().height(),
                proof.clone(),
                stored_state_transition,
            )?;
        }
        Ok(())
    }

    async fn process_sequencer_commitments(
        &self,
        l1_block: Da::FilteredBlock,
        sequencer_commitments: Vec<SequencerCommitment>,
    ) -> anyhow::Result<()> {
        for sequencer_commitment in sequencer_commitments.iter() {
            let start_l1_height =
                get_da_block_by_hash(&self.da_service, sequencer_commitment.l1_start_block_hash)
                    .await?
                    .header()
                    .height();

            let end_l1_height =
                get_da_block_by_hash(&self.da_service, sequencer_commitment.l1_end_block_hash)
                    .await?
                    .header()
                    .height();

            let start_l2_height = match self
                .ledger_db
                .get_l2_range_by_l1_height(SlotNumber(start_l1_height))?
            {
                Some((start_l2_height, _)) => start_l2_height,
                None => {
                    tracing::warn!(
                        "Sequencer commitment verification: L1 L2 connection does not exist. L1 height = {}. Skipping commitment.",
                        start_l1_height
                    );
                    continue;
                }
            };

            let end_l2_height = match self
                .ledger_db
                .get_l2_range_by_l1_height(SlotNumber(end_l1_height))?
            {
                Some((_, end_l2_height)) => BatchNumber(end_l2_height.0 + 1),
                None => {
                    tracing::warn!(
                        "Sequencer commitment verification: L1 L2 connection does not exist. L1 height = {}. Skipping commitment.",
                        end_l1_height
                    );
                    continue;
                }
            };

            tracing::info!(
                "Processing sequencer commitment. L2 Range = {:?} - {:?}. L1 Range = {} - {}",
                start_l2_height,
                end_l2_height,
                start_l1_height,
                end_l1_height
            );

            // Traverse each item's field of vector of transactions, put them in merkle tree
            // and compare the root with the one from the ledger
            let stored_soft_batches: Vec<StoredSoftBatch> = self
                .ledger_db
                .get_soft_batch_range(&(start_l2_height..end_l2_height))?;

            let soft_batches_tree = MerkleTree::<Sha256>::from_leaves(
                stored_soft_batches
                    .iter()
                    .map(|x| x.hash)
                    .collect::<Vec<_>>()
                    .as_slice(),
            );

            if soft_batches_tree.root() != Some(sequencer_commitment.merkle_root) {
                tracing::warn!(
                    "Merkle root mismatch - expected 0x{} but got 0x{}. Skipping commitment.",
                    hex::encode(
                        soft_batches_tree
                            .root()
                            .ok_or(anyhow!("Could not calculate soft batch tree root"))?
                    ),
                    hex::encode(sequencer_commitment.merkle_root)
                );
            } else {
                self.ledger_db.update_commitments_on_da_slot(
                    l1_block.header().height(),
                    sequencer_commitment.clone(),
                )?;

                for i in start_l1_height..=end_l1_height {
                    self.ledger_db.put_soft_confirmation_status(
                        SlotNumber(i),
                        SoftConfirmationStatus::Finalized,
                    )?;
                }
            }
        }
        Ok(())
    }

    async fn process_l2_block(
        &mut self,
        l2_height: u64,
        soft_batch: GetSoftBatchResponse,
        current_l1_block: Da::FilteredBlock,
    ) -> anyhow::Result<()> {
        info!(
            "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
            l2_height,
            hex::encode(soft_batch.hash),
            current_l1_block.header().height()
        );

        let mut data_to_commit = SlotCommit::new(current_l1_block.clone());

        let pre_state = self
            .storage_manager
            .create_storage_on_l2_height(l2_height)?;

        let slot_result = self.stf.apply_soft_batch(
            self.sequencer_pub_key.as_slice(),
            // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
            &self.state_root,
            pre_state,
            Default::default(),
            current_l1_block.header(),
            &current_l1_block.validity_condition(),
            &mut soft_batch.clone().into(),
        );

        let next_state_root = slot_result.state_root;
        // Check if post state root is the same as the one in the soft batch
        if next_state_root.as_ref().to_vec() != soft_batch.post_state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        for receipt in slot_result.batch_receipts {
            data_to_commit.add_batch(receipt);
        }

        self.storage_manager
            .save_change_set_l2(l2_height, slot_result.change_set)?;

        let batch_receipt = data_to_commit.batch_receipts()[0].clone();

        let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
            pre_state_root: self.state_root.as_ref().to_vec(),
            post_state_root: next_state_root.as_ref().to_vec(),
            phantom_data: PhantomData::<u64>,
            batch_hash: batch_receipt.batch_hash,
            da_slot_hash: current_l1_block.header().hash(),
            da_slot_height: current_l1_block.header().height(),
            da_slot_txs_commitment: current_l1_block.header().txs_commitment(),
            tx_receipts: batch_receipt.tx_receipts,
            soft_confirmation_signature: soft_batch.soft_confirmation_signature,
            pub_key: soft_batch.pub_key,
            deposit_data: soft_batch.deposit_data.into_iter().map(|x| x.tx).collect(),
            l1_fee_rate: soft_batch.l1_fee_rate,
            timestamp: soft_batch.timestamp,
        };

        self.ledger_db
            .commit_soft_batch(soft_batch_receipt, self.include_tx_body)?;

        self.ledger_db.extend_l2_range_of_l1_slot(
            SlotNumber(current_l1_block.header().height()),
            BatchNumber(l2_height),
        )?;

        self.state_root = next_state_root;

        info!(
            "New State Root after soft confirmation #{} is: {:?}",
            l2_height, self.state_root
        );

        self.storage_manager.finalize_l2(l2_height)?;

        Ok(())
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let (l1_tx, mut l1_rx) = mpsc::channel(1);
        let l1_sync_worker = sync_l1(self.start_l1_height, self.da_service.clone(), l1_tx);
        tokio::pin!(l1_sync_worker);

        let (l2_tx, mut l2_rx) = mpsc::channel(1);
        let l2_sync_worker =
            sync_l2::<Da>(self.start_l2_height, self.sequencer_client.clone(), l2_tx);
        tokio::pin!(l2_sync_worker);

        loop {
            select! {
                _ = &mut l1_sync_worker => {},
                _ = &mut l2_sync_worker => {},
                Some(l1_block) = l1_rx.recv() => {
                    // Set the l1 height of the l1 hash
                    self.ledger_db
                        .set_l1_height_of_l1_hash(l1_block.header().hash().into(), l1_block.header().height())
                        .unwrap();

                    // Merkle root hash - L1 start height - L1 end height
                    // TODO: How to confirm this is what we submit - use?
                    // TODO: Add support for multiple commitments in a single block

                    let mut sequencer_commitments = Vec::<SequencerCommitment>::new();
                    let mut zk_proofs = Vec::<Proof>::new();

                    self.da_service
                        .extract_relevant_blobs(&l1_block)
                        .into_iter()
                        .for_each(|mut tx| {
                            let data = DaData::try_from_slice(tx.full_data());
                            // Check for commitment
                            if tx.sender().as_ref() == self.sequencer_da_pub_key.as_slice() {
                                if let Ok(DaData::SequencerCommitment(seq_com)) = data {
                                    sequencer_commitments.push(seq_com);
                                } else {
                                    tracing::warn!(
                                        "Found broken DA data in block 0x{}: {:?}",
                                        hex::encode(l1_block.hash()),
                                        data
                                    );
                                }
                            }
                            let data = DaData::try_from_slice(tx.full_data());
                            // Check for proof
                            if tx.sender().as_ref() == self.prover_da_pub_key.as_slice() {
                                if let Ok(DaData::ZKProof(proof)) = data {
                                    zk_proofs.push(proof);
                                } else {
                                    tracing::warn!(
                                        "Found broken DA data in block 0x{}: {:?}",
                                        hex::encode(l1_block.hash()),
                                        data
                                    );
                                }
                            } else {
                                warn!("Force transactions are not implemented yet");
                                // TODO: This is where force transactions will land - try to parse DA data force transaction
                            }
                        });

                    if let Err(e) = self.process_zk_proofs(l1_block.clone(), zk_proofs).await {
                        error!("Could not process ZK proofs: {}", e);
                    }
                    if let Err(e) = self.process_sequencer_commitments(l1_block.clone(), sequencer_commitments).await {
                        error!("Could not process sequencer commitments: {}", e);
                    }
                },
                Some((l2_height, l2_block)) = l2_rx.recv() => {
                    let l1_block = get_da_block_at_height(&self.da_service, l2_block.da_slot_height).await?;
                    if let Err(e) = self.process_l2_block(l2_height, l2_block, l1_block).await {
                        error!("Could not process L2 block: {}", e);
                    }
                },
            }
        }
    }
}

async fn sync_l1<Da>(start_l1_height: u64, da_service: Da, sender: mpsc::Sender<Da::FilteredBlock>)
where
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
            let l1_block = match get_da_block_at_height(&da_service, block_number).await {
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
    sender: mpsc::Sender<(u64, GetSoftBatchResponse)>,
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

        let soft_batch = match retry_backoff(exponential_backoff.clone(), || async move {
            match inner_client.get_soft_batch::<Da::Spec>(l2_height).await {
                Ok(Some(soft_batch)) => Ok(soft_batch),
                Ok(None) => {
                    debug!("Soft Batch: no batch at height {}, retrying...", l2_height);

                    // We wait for 2 seconds and then return a Permanent error so that we exit the retry.
                    // This should not backoff exponentially
                    sleep(Duration::from_secs(1)).await;
                    Err(backoff::Error::Permanent(
                        "No soft batch published".to_owned(),
                    ))
                }
                Err(e) => match e.downcast_ref::<JsonrpseeError>() {
                    Some(JsonrpseeError::Transport(e)) => {
                        let error_msg =
                            format!("Soft Batch: connection error during RPC call: {:?}", e);
                        debug!(error_msg);
                        Err(backoff::Error::Transient {
                            err: error_msg,
                            retry_after: None,
                        })
                    }
                    _ => Err(backoff::Error::Transient {
                        err: format!("Soft Batch: unknown error from RPC call: {:?}", e),
                        retry_after: None,
                    }),
                },
            }
        })
        .await
        {
            Ok(soft_batch) => soft_batch,
            Err(_) => {
                continue;
            }
        };

        if let Err(e) = sender.send((l2_height, soft_batch)).await {
            error!("Could not notify about L2 block: {}", e);
        }
        l2_height += 1;
    }
}

async fn get_da_block_at_height<Da: DaService>(
    da_service: &Da,
    height: u64,
) -> anyhow::Result<Da::FilteredBlock> {
    let exponential_backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .build();

    retry_backoff(exponential_backoff.clone(), || async {
        da_service
            .get_block_at(height)
            .await
            .map_err(backoff::Error::transient)
    })
    .await
    .map_err(|e| anyhow!("Error while fetching L1 block: {}", e))
}

async fn get_da_block_by_hash<Da: DaService>(
    da_service: &Da,
    block_hash: [u8; 32],
) -> anyhow::Result<Da::FilteredBlock> {
    let exponential_backoff = ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .build();
    retry_backoff(exponential_backoff.clone(), || async {
        da_service
            .get_block_by_hash(block_hash)
            .await
            .map_err(backoff::Error::transient)
    })
    .await
    .map_err(|e| anyhow!("Could not fetch L1 block by hash: {}", e))
}
