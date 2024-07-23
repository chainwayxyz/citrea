use core::panic;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use borsh::de::BorshDeserialize;
use citrea_primitives::types::SoftConfirmationHash;
use citrea_primitives::{get_da_block_at_height, L1BlockCache};
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::RpcModule;
use rand::Rng;
use sequencer_client::{GetSoftBatchResponse, SequencerClient};
use shared_backup_db::{DbPoolError, PostgresConnector, ProofType};
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredStateTransition};
use sov_modules_api::storage::HierarchicalStorageManager;
use sov_modules_api::{BlobReaderTrait, Context, SignedSoftConfirmationBatch, SlotData};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
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

pub struct CitreaProver<C, Da, Sm, Vm, Stf, Ps>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,

    Ps: ProverService<Vm>,
{
    start_l2_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    /// made pub so that sequencer can clone it
    pub ledger_db: LedgerDB,
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
    code_commitment: Vm::CodeCommitment,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    soft_confirmation_tx: broadcast::Sender<u64>,
}

impl<C, Da, Sm, Vm, Stf, Ps> CitreaProver<C, Da, Sm, Vm, Stf, Ps>
where
    C: Context,
    Da: DaService<Error = anyhow::Error> + Clone + Send + Sync + 'static,
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
        prover_service: Option<Ps>,
        prover_config: Option<ProverConfig>,
        code_commitment: Vm::CodeCommitment,
        sync_blocks_count: u64,
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
        let last_soft_batch_processed_before_shutdown = item_numbers.soft_batch_number;
        // Last L1/L2 height before shutdown.
        let start_l2_height = last_soft_batch_processed_before_shutdown;

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
            code_commitment,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            sync_blocks_count,
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

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(&mut self) -> Result<(), anyhow::Error> {
        let skip_submission_until_l1 = std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1")
            .map_or(0u64, |v| v.parse().unwrap_or(0));

        // Prover node should sync when a new sequencer commitment arrives
        // Check da block get and sync up to the latest block in the latest commitment
        let last_scanned_l1_height = self
            .ledger_db
            .get_prover_last_scanned_l1_height()
            .unwrap_or_else(|_| panic!("Failed to get last scanned l1 height from the ledger db"));

        let start_l1_height = match last_scanned_l1_height {
            Some(height) => height.0,
            None => get_initial_slot_height::<Da::Spec>(&self.sequencer_client).await,
        };

        let prover_config = self.prover_config.clone().unwrap();

        let pg_client = match prover_config.clone().db_config {
            Some(db_config) => {
                info!("Connecting to postgres");
                Some(PostgresConnector::new(db_config.clone()).await)
            }
            None => None,
        };

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
                        &pg_client, &prover_config,
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
        soft_batch: GetSoftBatchResponse,
        current_l1_block: Da::FilteredBlock,
    ) -> anyhow::Result<()> {
        info!(
            "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
            l2_height,
            hex::encode(soft_batch.hash),
            current_l1_block.header().height()
        );

        if self.batch_hash != soft_batch.prev_hash {
            bail!("Previous hash mismatch at height: {}", l2_height);
        }

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
        if next_state_root.as_ref().to_vec() != soft_batch.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        // Save witness data to ledger db
        self.ledger_db
            .set_l2_witness(l2_height, &slot_result.witness)?;

        for receipt in slot_result.batch_receipts {
            data_to_commit.add_batch(receipt);
        }

        self.storage_manager
            .save_change_set_l2(l2_height, slot_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        let batch_receipt = data_to_commit.batch_receipts()[0].clone();

        let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
            state_root: next_state_root.as_ref().to_vec(),
            phantom_data: PhantomData::<u64>,
            hash: soft_batch.hash,
            prev_hash: soft_batch.prev_hash,
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

        self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;

        self.ledger_db.extend_l2_range_of_l1_slot(
            SlotNumber(current_l1_block.header().height()),
            BatchNumber(l2_height),
        )?;

        // Only errors when there are no receivers
        let _ = self.soft_confirmation_tx.send(l2_height);

        self.state_root = next_state_root;
        self.batch_hash = soft_batch.hash;

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
        pg_client: &Option<Result<PostgresConnector, DbPoolError>>,
        prover_config: &ProverConfig,
    ) -> Result<(), anyhow::Error> {
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

            let mut da_data = self.da_service.extract_relevant_blobs(l1_block);
            // if we don't do this, the zk circuit can't read the sequencer commitments
            da_data.iter_mut().for_each(|blob| {
                blob.full_data();
            });
            let sequencer_commitments: Vec<SequencerCommitment> =
                self.extract_sequencer_commitments(l1_block.header().hash().into(), &mut da_data);

            if sequencer_commitments.is_empty() {
                info!("No sequencer commitment found at height {}", l1_height,);
                self.ledger_db
                    .set_prover_last_scanned_l1_height(SlotNumber(l1_height))
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

            let first_l2_height_of_l1 = sequencer_commitments[0].l2_start_block_number;
            let last_l2_height_of_l1 =
                sequencer_commitments[sequencer_commitments.len() - 1].l2_end_block_number;

            // If the L2 range does not exist, we break off the local loop getting back to to
            // the outer loop / select to make room for other tasks to run.
            // We retry the L1 block there as well.
            if !self.check_l2_range_exists(first_l2_height_of_l1, last_l2_height_of_l1) {
                break;
            }

            let (
                state_transition_witnesses,
                soft_confirmations,
                da_block_headers_of_soft_confirmations,
            ) = self
                .get_state_transition_data_from_commitments(
                    &sequencer_commitments,
                    &self.da_service,
                )
                .await?;

            let da_block_header_of_commitments = l1_block.header().clone();

            let hash = da_block_header_of_commitments.hash();
            let initial_state_root = self
                .ledger_db
                .get_l2_state_root::<Stf::StateRoot>(first_l2_height_of_l1 - 1)?
                .expect("There should be a state root");
            let initial_batch_hash = self
                .ledger_db
                .get_soft_batch_by_number(&BatchNumber(first_l2_height_of_l1))?
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
                    sequencer_commitments_range: (
                        0,
                        (sequencer_commitments.len() - 1)
                            .try_into()
                            .expect("cant be more than 4 billion commitments in a da block; qed"),
                    ), // for now process all commitments
                    sequencer_public_key: self.sequencer_pub_key.clone(),
                    sequencer_da_public_key: self.sequencer_da_pub_key.clone(),
                };

            let should_prove: bool = {
                let mut rng = rand::thread_rng();
                // if proof_sampling_number is 0, then we always prove and submit
                // otherwise we submit and prove with a probability of 1/proof_sampling_number
                if prover_config.proof_sampling_number == 0 {
                    true
                } else {
                    rng.gen_range(0..prover_config.proof_sampling_number) == 0
                }
            };

            // Skip submission until l1 height
            if l1_height >= skip_submission_until_l1 && should_prove {
                self.generate_and_submit_proof(transition_data, pg_client, l1_height, hash)
                    .await?;
            } else {
                info!("Skipping proving for l1 height {}", l1_height);
            }
            self.save_commitments(sequencer_commitments, l1_height);

            if let Err(e) = self
                .ledger_db
                .set_prover_last_scanned_l1_height(SlotNumber(l1_height))
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
        da_service: &Da,
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
            let soft_batches_in_commitment = match self
                .ledger_db
                .get_soft_batch_range(&(BatchNumber(start_l2)..BatchNumber(end_l2 + 1)))
            {
                Ok(soft_batches) => soft_batches,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to get soft batches from the ledger db: {}",
                        e
                    ));
                }
            };
            let mut commitment_soft_confirmations = vec![];
            let mut da_block_headers_to_push: Vec<
                <<Da as DaService>::Spec as DaSpec>::BlockHeader,
            > = vec![];
            for soft_batch in soft_batches_in_commitment {
                if da_block_headers_to_push.is_empty()
                    || da_block_headers_to_push.last().unwrap().height()
                        != soft_batch.da_slot_height
                {
                    let filtered_block = match get_da_block_at_height(
                        da_service,
                        soft_batch.da_slot_height,
                        self.l1_block_cache.clone(),
                    )
                    .await
                    {
                        Ok(block) => block,
                        Err(_) => {
                            return Err(anyhow!(
                                "Error while fetching DA block at height: {}",
                                soft_batch.da_slot_height
                            ));
                        }
                    };
                    da_block_headers_to_push.push(filtered_block.header().clone());
                }
                let signed_soft_confirmation: SignedSoftConfirmationBatch =
                    soft_batch.clone().into();
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
        if let Ok(range) = ledger_db.clone().get_soft_batch_range(
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
        pg_client: &Option<Result<PostgresConnector, DbPoolError>>,
        l1_height: u64,
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

        let tx_id_u8 = tx_id.into();

        // l1_height => (tx_id, proof, transition_data)
        // save proof along with tx id to db, should be queriable by slot number or slot hash
        let transition_data: sov_modules_api::StateTransition<
            <Da as DaService>::Spec,
            Stf::StateRoot,
        > = Vm::extract_output(&proof).expect("Proof should be deserializable");

        match proof {
            Proof::PublicInput(_) => {
                warn!("Proof is public input, skipping");
            }
            Proof::Full(ref proof) => {
                info!("Verifying proof!");
                let transition_data_from_proof =
                    Vm::verify_and_extract_output::<<Da as DaService>::Spec, Stf::StateRoot>(
                        &proof.clone(),
                        &self.code_commitment,
                    )
                    .expect("Proof should be verifiable");

                info!(
                    "transition data from proof: {:?}",
                    transition_data_from_proof
                );
            }
        }

        info!("transition data: {:?}", transition_data);

        let stored_state_transition = StoredStateTransition {
            initial_state_root: transition_data.initial_state_root.as_ref().to_vec(),
            final_state_root: transition_data.final_state_root.as_ref().to_vec(),
            state_diff: transition_data.state_diff,
            da_slot_hash: transition_data.da_slot_hash.into(),
            sequencer_commitments_range: transition_data.sequencer_commitments_range,
            sequencer_public_key: transition_data.sequencer_public_key,
            sequencer_da_public_key: transition_data.sequencer_da_public_key,
            validity_condition: borsh::to_vec(&transition_data.validity_condition).unwrap(),
        };

        match pg_client.as_ref() {
            Some(Ok(pool)) => {
                info!("Inserting proof data into postgres");
                let (proof_data, proof_type) = match proof.clone() {
                    Proof::Full(full_proof) => (full_proof, ProofType::Full),
                    Proof::PublicInput(public_input) => (public_input, ProofType::PublicInput),
                };
                pool.insert_proof_data(
                    tx_id_u8.to_vec(),
                    proof_data,
                    stored_state_transition.clone().into(),
                    proof_type,
                )
                .await
                .unwrap();
            }
            _ => {
                warn!("No postgres client found");
            }
        }

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
}

async fn l1_sync<Da>(
    start_l1_height: u64,
    da_service: Da,
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
    sender: mpsc::Sender<Vec<(u64, GetSoftBatchResponse)>>,
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
        let soft_batches: Vec<GetSoftBatchResponse> =
            match retry_backoff(exponential_backoff.clone(), || async move {
                let soft_batches = inner_client
                    .get_soft_batch_range::<Da::Spec>(l2_height..l2_height + sync_blocks_count)
                    .await;

                match soft_batches {
                    Ok(soft_batches) => Ok(soft_batches.into_iter().flatten().collect::<Vec<_>>()),
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
                Ok(soft_batches) => soft_batches,
                Err(_) => {
                    continue;
                }
            };

        if soft_batches.is_empty() {
            debug!(
                "Soft Batch: no batch at starting height {}, retrying...",
                l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let soft_batches: Vec<(u64, GetSoftBatchResponse)> = (l2_height
            ..l2_height + soft_batches.len() as u64)
            .zip(soft_batches)
            .collect();

        l2_height += soft_batches.len() as u64;

        if let Err(e) = sender.send(soft_batches).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}

async fn get_initial_slot_height<Da: DaSpec>(client: &SequencerClient) -> u64 {
    loop {
        match client.get_soft_batch::<Da>(1).await {
            Ok(Some(batch)) => return batch.da_slot_height,
            _ => {
                // sleep 1
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
}
