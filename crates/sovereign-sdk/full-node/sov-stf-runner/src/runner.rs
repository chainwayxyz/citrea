use std::collections::VecDeque;
use std::marker::PhantomData;
use std::net::SocketAddr;

use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use borsh::de::BorshDeserialize;
use borsh::BorshSerialize as _;
use hyper::Method;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::server::middleware::http::ProxyGetRequestLayer;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::RpcModule;
use rand::Rng;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sequencer_client::{GetSoftBatchResponse, SequencerClient};
use shared_backup_db::{PostgresConnector, ProofType};
use sov_db::ledger_db::{LedgerDB, SlotCommit};
use sov_db::schema::types::{BatchNumber, SlotNumber, StoredSoftBatch, StoredStateTransition};
use sov_modules_api::{Context, SignedSoftConfirmationBatch};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaData, DaSpec, SequencerCommitment,
};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
pub use sov_rollup_interface::stf::BatchReceipt;
use sov_rollup_interface::stf::{SoftBatchReceipt, StateTransitionFunction};
use sov_rollup_interface::storage::HierarchicalStorageManager;
use sov_rollup_interface::zk::{Proof, StateTransitionData, Zkvm, ZkvmHost};
use tokio::sync::oneshot;
use tokio::time::{sleep, Duration};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};

use crate::prover_helpers::get_initial_slot_height;
use crate::verifier::StateTransitionVerifier;
use crate::{ProverConfig, ProverService, RollupPublicKeys, RpcConfig, RunnerConfig};

type StateRoot<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::StateRoot;
type GenesisParams<ST, Vm, Da> = <ST as StateTransitionFunction<Vm, Da>>::GenesisParams;

/// Combines `DaService` with `StateTransitionFunction` and "runs" the rollup.
pub struct StateTransitionRunner<Stf, Sm, Da, Vm, Ps, C>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Stf: StateTransitionFunction<Vm, Da::Spec, Condition = <Da::Spec as DaSpec>::ValidityCondition>
        + StfBlueprintTrait<C, Da::Spec, Vm>,
    Ps: ProverService<Vm>,
    C: Context,
{
    start_height: u64,
    da_service: Da,
    stf: Stf,
    storage_manager: Sm,
    /// made pub so that sequencer can clone it
    pub ledger_db: LedgerDB,
    state_root: StateRoot<Stf, Vm, Da::Spec>,
    rpc_config: RpcConfig,
    #[allow(dead_code)]
    prover_service: Option<Ps>,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    include_tx_body: bool,
    prover_config: Option<ProverConfig>,
    code_commitment: Vm::CodeCommitment,
    accept_public_input_as_proven: bool,
}

/// Represents the possible modes of execution for a zkVM program
pub enum ProofGenConfig<Stf, Da: DaService, Vm: ZkvmHost>
where
    Stf: StateTransitionFunction<Vm::Guest, Da::Spec>,
{
    /// Skips proving.
    Skip,
    /// The simulator runs the rollup verifier logic without even emulating the zkVM
    Simulate(StateTransitionVerifier<Stf, Da::Verifier, Vm::Guest>),
    /// The executor runs the rollup verification logic in the zkVM, but does not actually
    /// produce a zk proof
    Execute,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk proof
    Prover,
}

/// How [`StateTransitionRunner`] is initialized
pub enum InitVariant<Stf: StateTransitionFunction<Vm, Da>, Vm: Zkvm, Da: DaSpec> {
    /// From give state root
    Initialized(Stf::StateRoot),
    /// From empty state root
    /// Genesis params for Stf::init
    Genesis(GenesisParams<Stf, Vm, Da>),
}

impl<Stf, Sm, Da, Vm, Ps, C> StateTransitionRunner<Stf, Sm, Da, Vm, Ps, C>
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
        let last_soft_batch_processed_before_shutdown = item_numbers.soft_batch_number;

        let start_height = last_soft_batch_processed_before_shutdown;

        Ok(Self {
            start_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: prev_state_root,
            rpc_config,
            prover_service,
            sequencer_client: SequencerClient::new(runner_config.sequencer_client_url),
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            prover_da_pub_key: public_keys.prover_da_pub_key,
            phantom: std::marker::PhantomData,
            include_tx_body: runner_config.include_tx_body,
            prover_config,
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

        let methods = self
            .register_healthcheck_rpc(methods)
            .expect("Failed to register healthcheck rpc");

        let cors = CorsLayer::new()
            .allow_methods([Method::POST, Method::OPTIONS])
            .allow_origin(Any)
            .allow_headers(Any);
        let health_check = ProxyGetRequestLayer::new("/health", "health_check").unwrap();
        let middleware = tower::ServiceBuilder::new().layer(cors).layer(health_check);

        let _handle = tokio::spawn(async move {
            let server = jsonrpsee::server::ServerBuilder::default()
                .max_connections(max_connections)
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

    /// Updates the given RpcModule with healthcheckk rpc.
    fn register_healthcheck_rpc(
        &self,
        mut rpc_methods: RpcModule<()>,
    ) -> Result<RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        // TODO: create register_healthcheck_rpc helper function
        let ledger_db = self.ledger_db.clone();
        rpc_methods.register_async_method("health_check", move |_, _| {
            let ledger_db = ledger_db.clone();
            async move {
                let head_batch = ledger_db.get_head_soft_batch().map_err(|err| {
                    ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some(format!("Failed to get head soft batch: {}", err)),
                    )
                })?;
                let head_batch_num: u64 = match head_batch {
                    Some((i, _)) => i.into(),
                    None => return Ok::<(), ErrorObjectOwned>(()),
                };
                if head_batch_num < 1 {
                    return Ok::<(), ErrorObjectOwned>(());
                }

                let soft_batches = ledger_db
                    .get_soft_batch_range(
                        &(BatchNumber(head_batch_num - 1)..BatchNumber(head_batch_num + 1)),
                    )
                    .map_err(|err| {
                        ErrorObjectOwned::owned(
                            INTERNAL_ERROR_CODE,
                            INTERNAL_ERROR_MSG,
                            Some(format!("Failed to get soft batch range: {}", err)),
                        )
                    })?;
                let block_time_s = soft_batches[1].timestamp - soft_batches[0].timestamp;
                tokio::time::sleep(Duration::from_millis(block_time_s * 1500)).await;

                let (new_head_batch_num, _) = ledger_db
                    .get_head_soft_batch()
                    .map_err(|err| {
                        ErrorObjectOwned::owned(
                            INTERNAL_ERROR_CODE,
                            INTERNAL_ERROR_MSG,
                            Some(format!("Failed to get head soft batch: {}", err)),
                        )
                    })?
                    .unwrap();
                if new_head_batch_num > BatchNumber(head_batch_num) {
                    Ok::<(), ErrorObjectOwned>(())
                } else {
                    Err(ErrorObjectOwned::owned(
                        INTERNAL_ERROR_CODE,
                        INTERNAL_ERROR_MSG,
                        Some("Block number is not increasing"),
                    ))
                }
            }
        })?;

        Ok(rpc_methods)
    }

    /// Returns the head soft batch
    #[instrument(level = "trace", skip_all, err)]
    pub fn get_head_soft_batch(&self) -> anyhow::Result<Option<(BatchNumber, StoredSoftBatch)>> {
        self.ledger_db.get_head_soft_batch()
    }

    /// Runs the prover process.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run_prover_process(&mut self) -> Result<(), anyhow::Error> {
        let skip_submission_until_l1 = std::env::var("SKIP_PROOF_SUBMISSION_UNTIL_L1")
            .map_or(0u64, |v| v.parse().unwrap_or(0));

        // Prover node should sync when a new sequencer commitment arrives
        // Check da block get and sync up to the latest block in the latest commitment
        let last_scanned_l1_height = self
            .ledger_db
            .get_prover_last_scanned_l1_height()
            .unwrap_or_else(|_| panic!("Failed to get last scanned l1 height from the ledger db"));

        let mut l1_height = match last_scanned_l1_height {
            Some(height) => height.0 + 1,
            None => get_initial_slot_height::<Da::Spec>(&self.sequencer_client).await,
        };

        let mut l2_height = self.start_height;

        let prover_config = self.prover_config.clone().unwrap();

        let pg_client = match prover_config.db_config {
            Some(db_config) => {
                tracing::info!("Connecting to postgres");
                Some(PostgresConnector::new(db_config.clone()).await)
            }
            None => None,
        };

        loop {
            let da_service = &self.da_service;

            let exponential_backoff = ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_secs(1))
                .with_max_elapsed_time(Some(Duration::from_secs(5 * 60)))
                .build();
            let last_finalized_height = retry_backoff(exponential_backoff.clone(), || async {
                da_service
                    .get_last_finalized_block_header()
                    .await
                    .map_err(backoff::Error::transient)
            })
            .await?
            .height();

            if l1_height > last_finalized_height {
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            let filtered_block = retry_backoff(exponential_backoff.clone(), || async {
                da_service
                    .get_block_at(l1_height)
                    .await
                    .map_err(backoff::Error::transient)
            })
            .await?;

            // map the height to the hash
            self.ledger_db
                .set_l1_height_of_l1_hash(filtered_block.header().hash().into(), l1_height)
                .unwrap();

            let mut sequencer_commitments = Vec::<SequencerCommitment>::new();
            let mut zk_proofs = Vec::<Proof>::new();

            self.da_service
                .extract_relevant_blobs(&filtered_block)
                .into_iter()
                .for_each(|mut tx| {
                    let data = DaData::try_from_slice(tx.full_data());

                    if tx.sender().as_ref() == self.sequencer_da_pub_key.as_slice() {
                        if let Ok(DaData::SequencerCommitment(seq_com)) = data {
                            sequencer_commitments.push(seq_com);
                        } else {
                            tracing::warn!(
                                "Found broken DA data in block 0x{}: {:?}",
                                hex::encode(filtered_block.hash()),
                                data
                            );
                        }
                    } else if tx.sender().as_ref() == self.prover_da_pub_key.as_slice() {
                        if let Ok(DaData::ZKProof(proof)) = data {
                            zk_proofs.push(proof);
                        } else {
                            tracing::warn!(
                                "Found broken DA data in block 0x{}: {:?}",
                                hex::encode(filtered_block.hash()),
                                data
                            );
                        }
                    } else {
                        warn!("Force transactions are not implemented yet");
                        // TODO: This is where force transactions will land - try to parse DA data force transaction
                    }
                });

            if !zk_proofs.is_empty() {
                warn!("ZK proofs are not empty");
                // TODO: Implement this
            }

            if sequencer_commitments.is_empty() {
                tracing::info!("No sequencer commitment found at height {}", l1_height,);

                self.ledger_db
                    .set_prover_last_scanned_l1_height(SlotNumber(l1_height))
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to put prover last scanned l1 height in the ledger db {}",
                            l1_height
                        )
                    });

                l1_height += 1;
                continue;
            }

            tracing::info!(
                "Processing {} sequencer commitments at height {}",
                sequencer_commitments.len(),
                filtered_block.header().height(),
            );

            let initial_state_root = self.state_root.clone();

            let mut da_data = self.da_service.extract_relevant_blobs(&filtered_block);
            let da_block_header_of_commitments = filtered_block.header().clone();
            let (inclusion_proof, completeness_proof) = self
                .da_service
                .get_extraction_proof(&filtered_block, &da_data)
                .await;

            // if we don't do this, the zk circuit can't read the sequencer commitments
            da_data.iter_mut().for_each(|blob| {
                blob.full_data();
            });

            let mut soft_confirmations: VecDeque<Vec<SignedSoftConfirmationBatch>> =
                VecDeque::new();
            let mut state_transition_witnesses: VecDeque<Vec<Stf::Witness>> = VecDeque::new();
            let mut da_block_headers_of_soft_confirmations: VecDeque<
                Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>,
            > = VecDeque::new();

            let mut traversed_l1_tuples = vec![];

            for sequencer_commitment in sequencer_commitments.clone().into_iter() {
                let mut sof_soft_confirmations_to_push = vec![];
                let mut state_transition_witnesses_to_push = vec![];
                let mut da_block_headers_to_push: Vec<
                    <<Da as DaService>::Spec as DaSpec>::BlockHeader,
                > = vec![];

                let start_l1_height = retry_backoff(exponential_backoff.clone(), || async {
                    da_service
                        .get_block_by_hash(sequencer_commitment.l1_start_block_hash)
                        .await
                        .map_err(backoff::Error::transient)
                })
                .await?
                .header()
                .height();

                let end_l1_height = retry_backoff(exponential_backoff.clone(), || async {
                    da_service
                        .get_block_by_hash(sequencer_commitment.l1_end_block_hash)
                        .await
                        .map_err(backoff::Error::transient)
                })
                .await?
                .header()
                .height();
                traversed_l1_tuples.push((start_l1_height, end_l1_height));

                // start fetching blocks from sequencer, when you see a soft batch with l1 height more than end_l1_height, stop
                // while getting the blocks to all the same ops as full node
                // after stopping call continue  and look for a new seq_commitment
                // change the itemnumbers only after the sync is done so not for every da block

                loop {
                    let inner_client = &self.sequencer_client;
                    let soft_batch =
                        match retry_backoff(exponential_backoff.clone(), || async move {
                            match inner_client.get_soft_batch::<Da::Spec>(l2_height).await {
                                Ok(Some(soft_batch)) => Ok(soft_batch),
                                Ok(None) => {
                                    debug!(
                                        "Soft Batch: no batch at height {}, retrying...",
                                        l2_height
                                    );

                                    // We wait for 2 seconds and then return a Permanent error so that we exit the retry.
                                    // This should not backoff exponentially
                                    sleep(Duration::from_secs(2)).await;
                                    Err(backoff::Error::Permanent(
                                        "No soft batch published".to_owned(),
                                    ))
                                }
                                Err(e) => match e.downcast_ref::<JsonrpseeError>() {
                                    Some(JsonrpseeError::Transport(e)) => {
                                        let error_msg = format!(
                                            "Soft Batch: connection error during RPC call: {:?}",
                                            e
                                        );
                                        debug!(error_msg);
                                        Err(backoff::Error::Transient {
                                            err: error_msg,
                                            retry_after: None,
                                        })
                                    }
                                    _ => Err(backoff::Error::Transient {
                                        err: format!(
                                            "Soft Batch: unknown error from RPC call: {:?}",
                                            e
                                        ),
                                        retry_after: None,
                                    }),
                                },
                            }
                        })
                        .await
                        {
                            Ok(soft_batch) => soft_batch,
                            Err(_) => {
                                break;
                            }
                        };

                    if soft_batch.da_slot_height > end_l1_height {
                        break;
                    }

                    info!(
                        "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
                        l2_height,
                        hex::encode(soft_batch.hash),
                        soft_batch.da_slot_height
                    );

                    let mut signed_soft_confirmation: SignedSoftConfirmationBatch =
                        soft_batch.clone().into();

                    sof_soft_confirmations_to_push.push(signed_soft_confirmation.clone());

                    // The filtered block of soft batch, which is the block at the da_slot_height of soft batch
                    let filtered_block = retry_backoff(exponential_backoff.clone(), || async {
                        da_service
                            .get_block_at(soft_batch.da_slot_height)
                            .await
                            .map_err(backoff::Error::transient)
                    })
                    .await?;

                    if da_block_headers_to_push.is_empty()
                        || da_block_headers_to_push.last().unwrap().height()
                            != filtered_block.header().height()
                    {
                        da_block_headers_to_push.push(filtered_block.header().clone());
                    }

                    let mut data_to_commit = SlotCommit::new(filtered_block.clone());

                    let pre_state = self
                        .storage_manager
                        .create_storage_on_l2_height(l2_height)?;

                    let slot_result = self.stf.apply_soft_batch(
                        self.sequencer_pub_key.as_slice(),
                        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
                        &self.state_root,
                        pre_state,
                        Default::default(),
                        filtered_block.header(),
                        &filtered_block.validity_condition(),
                        &mut signed_soft_confirmation,
                    );

                    state_transition_witnesses_to_push.push(slot_result.witness);

                    for receipt in slot_result.batch_receipts {
                        data_to_commit.add_batch(receipt);
                    }

                    self.storage_manager
                        .save_change_set_l2(l2_height, slot_result.change_set)?;

                    let batch_receipt = data_to_commit.batch_receipts()[0].clone();

                    let next_state_root = slot_result.state_root;

                    // Check if post state root is the same as the one in the soft batch
                    if next_state_root.as_ref().to_vec() != soft_batch.post_state_root {
                        bail!("Post state root mismatch")
                    }

                    let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
                        pre_state_root: self.state_root.as_ref().to_vec(),
                        post_state_root: next_state_root.as_ref().to_vec(),
                        phantom_data: PhantomData::<u64>,
                        batch_hash: batch_receipt.batch_hash,
                        da_slot_hash: filtered_block.header().hash(),
                        da_slot_height: filtered_block.header().height(),
                        da_slot_txs_commitment: filtered_block.header().txs_commitment(),
                        tx_receipts: batch_receipt.tx_receipts,
                        soft_confirmation_signature: soft_batch.soft_confirmation_signature,
                        pub_key: soft_batch.pub_key,
                        deposit_data: soft_batch.deposit_data.into_iter().map(|x| x.tx).collect(),
                        l1_fee_rate: soft_batch.l1_fee_rate,
                        timestamp: soft_batch.timestamp,
                    };

                    self.ledger_db.commit_soft_batch(soft_batch_receipt, true)?;
                    self.ledger_db.extend_l2_range_of_l1_slot(
                        SlotNumber(filtered_block.header().height()),
                        BatchNumber(l2_height),
                    )?;

                    self.state_root = next_state_root;

                    info!(
                        "New State Root after soft confirmation #{} is: {:?}",
                        l2_height, self.state_root
                    );

                    self.storage_manager.finalize_l2(l2_height)?;

                    l2_height += 1;
                }

                soft_confirmations.push_back(sof_soft_confirmations_to_push);
                state_transition_witnesses.push_back(state_transition_witnesses_to_push);
                da_block_headers_of_soft_confirmations.push_back(da_block_headers_to_push);
            }

            tracing::info!("Sending for proving");

            let hash = da_block_header_of_commitments.hash();

            let transition_data: StateTransitionData<Stf::StateRoot, Stf::Witness, Da::Spec> =
                StateTransitionData {
                    initial_state_root,
                    final_state_root: self.state_root.clone(),
                    da_data,
                    da_block_header_of_commitments,
                    inclusion_proof,
                    completeness_proof,
                    soft_confirmations,
                    state_transition_witnesses,
                    da_block_headers_of_soft_confirmations,

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
                let prover_service = self
                    .prover_service
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Prover service is not initialized"))?;

                prover_service.submit_witness(transition_data).await;

                prover_service.prove(hash.clone()).await?;

                let (tx_id, proof) = prover_service
                    .wait_for_proving_and_send_to_da(hash.clone(), &self.da_service)
                    .await?;

                let tx_id_u8 = tx_id.into();

                // l1_height => (tx_id, proof, transition_data)
                // save proof along with tx id to db, should be queriable by slot number or slot hash
                let transition_data: sov_modules_api::StateTransition<
                    <Da as DaService>::Spec,
                    Stf::StateRoot,
                > = Vm::extract_output(&proof).expect("Proof should be deserializable");

                match proof {
                    Proof::PublicInput(_) => {
                        tracing::warn!("Proof is public input, skipping");
                    }
                    Proof::Full(ref proof) => {
                        tracing::info!("Verifying proof!");
                        let transition_data_from_proof = Vm::verify_and_extract_output::<
                            <Da as DaService>::Spec,
                            Stf::StateRoot,
                        >(
                            &proof.clone(), &self.code_commitment
                        )
                        .expect("Proof should be verifiable");

                        tracing::info!(
                            "transition data from proof: {:?}",
                            transition_data_from_proof
                        );
                    }
                }

                tracing::info!("transition data: {:?}", transition_data);

                let stored_state_transition = StoredStateTransition {
                    initial_state_root: transition_data.initial_state_root.as_ref().to_vec(),
                    final_state_root: transition_data.final_state_root.as_ref().to_vec(),
                    state_diff: transition_data.state_diff,
                    da_slot_hash: transition_data.da_slot_hash.into(),
                    sequencer_public_key: transition_data.sequencer_public_key,
                    sequencer_da_public_key: transition_data.sequencer_da_public_key,
                    validity_condition: transition_data.validity_condition.try_to_vec().unwrap(),
                };

                match pg_client.as_ref() {
                    Some(Ok(pool)) => {
                        tracing::info!("Inserting proof data into postgres");
                        let (proof_data, proof_type) = match proof.clone() {
                            Proof::Full(full_proof) => (full_proof, ProofType::Full),
                            Proof::PublicInput(public_input) => {
                                (public_input, ProofType::PublicInput)
                            }
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
                        tracing::warn!("No postgres client found");
                    }
                }

                self.ledger_db.put_proof_data(
                    l1_height,
                    tx_id_u8,
                    proof,
                    stored_state_transition,
                )?;
            } else {
                tracing::info!("Skipping proving for l1 height {}", l1_height);
            }

            for (sequencer_commitment, l1_heights) in
                sequencer_commitments.into_iter().zip(traversed_l1_tuples)
            {
                // Save commitments on prover ledger db
                self.ledger_db
                    .update_commitments_on_da_slot(l1_height, sequencer_commitment.clone())
                    .unwrap();

                for i in l1_heights.0..=l1_heights.1 {
                    self.ledger_db
                        .put_soft_confirmation_status(
                            SlotNumber(i),
                            SoftConfirmationStatus::Finalized,
                        )
                        .unwrap_or_else(|_| {
                            panic!(
                                "Failed to put soft confirmation status in the ledger db {}",
                                i
                            )
                        });
                }
            }

            self.ledger_db
                .set_prover_last_scanned_l1_height(SlotNumber(l1_height))?;
            l1_height += 1;
        }
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run_in_process(&mut self) -> Result<(), anyhow::Error> {
        let mut last_l1_height = 0;
        let mut cur_l1_block = None;

        let mut height = self.start_height;
        info!("Starting to sync from height {}", height);

        loop {
            let exponential_backoff = ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_secs(1))
                .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
                .build();
            let inner_client = &self.sequencer_client;
            let soft_batches: Vec<GetSoftBatchResponse> =
                match retry_backoff(exponential_backoff.clone(), || async move {
                    match inner_client
                        .get_soft_batch_range::<Da::Spec>(height..height + 10)
                        .await
                    {
                        Ok(soft_batches) => {
                            Ok(soft_batches.into_iter().flatten().collect::<Vec<_>>())
                        }
                        Err(e) => match e.downcast_ref::<JsonrpseeError>() {
                            Some(JsonrpseeError::Transport(e)) => {
                                let error_msg = format!(
                                    "Soft Batch: connection error during RPC call: {:?}",
                                    e
                                );
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
                    height
                );

                // We wait for 2 seconds and then return a Permanent error so that we exit the retry.
                // This should not backoff exponentially
                sleep(Duration::from_secs(2)).await;
                continue;
            }

            for soft_batch in soft_batches {
                if last_l1_height != soft_batch.da_slot_height || cur_l1_block.is_none() {
                    last_l1_height = soft_batch.da_slot_height;
                    // TODO: for a node, the da block at slot_height might not have been finalized yet
                    // should wait for it to be finalized
                    let da_service = &self.da_service;
                    let filtered_block = retry_backoff(exponential_backoff.clone(), || async {
                        da_service
                            .get_block_at(soft_batch.da_slot_height)
                            .await
                            .map_err(backoff::Error::transient)
                    })
                    .await?;

                    // Set the l1 height of the l1 hash
                    self.ledger_db
                        .set_l1_height_of_l1_hash(
                            filtered_block.header().hash().into(),
                            soft_batch.da_slot_height,
                        )
                        .unwrap();

                    // Merkle root hash - L1 start height - L1 end height
                    // TODO: How to confirm this is what we submit - use?
                    // TODO: Add support for multiple commitments in a single block

                    let mut sequencer_commitments = Vec::<SequencerCommitment>::new();
                    let mut zk_proofs = Vec::<Proof>::new();

                    self.da_service
                        .extract_relevant_blobs(&filtered_block)
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
                                        hex::encode(filtered_block.hash()),
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
                                        hex::encode(filtered_block.hash()),
                                        data
                                    );
                                }
                            } else {
                                warn!("Force transactions are not implemented yet");
                                // TODO: This is where force transactions will land - try to parse DA data force transaction
                            }
                        });

                    for proof in zk_proofs {
                        tracing::warn!("Processing zk proof: {:?}", proof);
                        let state_transition = match proof.clone() {
                            Proof::Full(proof) => {
                                let code_commitment = self.code_commitment.clone();

                                tracing::warn!(
                                    "using code commitment: {:?}",
                                    serde_json::to_string(&code_commitment).unwrap()
                                );

                                if let Ok(proof_data) =
                                    Vm::verify_and_extract_output::<
                                        <Da as DaService>::Spec,
                                        Stf::StateRoot,
                                    >(&proof, &code_commitment)
                                {
                                    if proof_data.sequencer_da_public_key
                                        != self.sequencer_da_pub_key
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
                                    tracing::warn!("Found public input in da block number: {:?}, Skipping to next proof..", soft_batch.da_slot_height);
                                    continue;
                                }
                                // public input is accepted only in tests, so ok to expect
                                Vm::extract_output(&proof).expect("Proof should be deserializable")
                            }
                        };

                        let stored_state_transition = StoredStateTransition {
                            initial_state_root: state_transition
                                .initial_state_root
                                .as_ref()
                                .to_vec(),
                            final_state_root: state_transition.final_state_root.as_ref().to_vec(),
                            state_diff: state_transition.state_diff,
                            da_slot_hash: state_transition.da_slot_hash.clone().into(),
                            sequencer_public_key: state_transition.sequencer_public_key,
                            sequencer_da_public_key: state_transition.sequencer_da_public_key,
                            validity_condition: state_transition
                                .validity_condition
                                .try_to_vec()
                                .unwrap(),
                        };

                        let l1_hash = state_transition.da_slot_hash.into();

                        // This is the l1 heidght where the sequencer commitment was read by the prover and proof generated by those commitments
                        // We need to get commitments in this l1 hegight and set them as proven
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
                        let proven_commitments = match self
                            .ledger_db
                            .get_commitments_on_da_slot(l1_height)?
                        {
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
                        let l1_height_start = match self
                            .ledger_db
                            .get_l1_height_of_l1_hash(first_slot_hash)?
                        {
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
                            soft_batch.da_slot_height,
                            proof.clone(),
                            stored_state_transition,
                        )?;
                    }

                    for sequencer_commitment in sequencer_commitments.iter() {
                        tracing::warn!(
                            "Processing sequencer commitment: {:?}",
                            sequencer_commitment
                        );
                        let start_l1_height =
                            retry_backoff(exponential_backoff.clone(), || async {
                                da_service
                                    .get_block_by_hash(sequencer_commitment.l1_start_block_hash)
                                    .await
                                    .map_err(backoff::Error::transient)
                            })
                            .await?
                            .header()
                            .height();

                        let end_l1_height = retry_backoff(exponential_backoff.clone(), || async {
                            da_service
                                .get_block_by_hash(sequencer_commitment.l1_end_block_hash)
                                .await
                                .map_err(backoff::Error::transient)
                        })
                        .await?
                        .header()
                        .height();

                        tracing::warn!(
                            "start height: {}, end height: {}",
                            start_l1_height,
                            end_l1_height
                        );

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
                            Some((_, end_l2_height)) => end_l2_height,
                            None => {
                                tracing::warn!(
                            "Sequencer commitment verification: L1 L2 connection does not exist. L1 height = {}. Skipping commitment.",
                            end_l1_height
                            );
                                continue;
                            }
                        };

                        let range_end = BatchNumber(end_l2_height.0 + 1);
                        // Traverse each item's field of vector of transactions, put them in merkle tree
                        // and compare the root with the one from the ledger
                        let stored_soft_batches: Vec<StoredSoftBatch> = self
                            .ledger_db
                            .get_soft_batch_range(&(start_l2_height..range_end))?;

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
                                soft_batch.da_slot_height,
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

                    cur_l1_block = Some(filtered_block);
                }

                let cur_l1_block = cur_l1_block.clone().unwrap();

                info!(
                    "Running soft confirmation batch #{} with hash: 0x{} on DA block #{}",
                    height,
                    hex::encode(soft_batch.hash),
                    cur_l1_block.header().height()
                );

                let mut data_to_commit = SlotCommit::new(cur_l1_block.clone());

                let pre_state = self.storage_manager.create_storage_on_l2_height(height)?;

                let slot_result = self.stf.apply_soft_batch(
                    self.sequencer_pub_key.as_slice(),
                    // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
                    &self.state_root,
                    pre_state,
                    Default::default(),
                    cur_l1_block.header(),
                    &cur_l1_block.validity_condition(),
                    &mut soft_batch.clone().into(),
                );

                let next_state_root = slot_result.state_root;
                // Check if post state root is the same as the one in the soft batch
                if next_state_root.as_ref().to_vec() != soft_batch.post_state_root {
                    warn!("Post state root mismatch at height: {}", height);
                    continue;
                }

                for receipt in slot_result.batch_receipts {
                    data_to_commit.add_batch(receipt);
                }

                self.storage_manager
                    .save_change_set_l2(height, slot_result.change_set)?;

                let batch_receipt = data_to_commit.batch_receipts()[0].clone();

                let soft_batch_receipt = SoftBatchReceipt::<_, _, Da::Spec> {
                    pre_state_root: self.state_root.as_ref().to_vec(),
                    post_state_root: next_state_root.as_ref().to_vec(),
                    phantom_data: PhantomData::<u64>,
                    batch_hash: batch_receipt.batch_hash,
                    da_slot_hash: cur_l1_block.header().hash(),
                    da_slot_height: cur_l1_block.header().height(),
                    da_slot_txs_commitment: cur_l1_block.header().txs_commitment(),
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
                    SlotNumber(cur_l1_block.header().height()),
                    BatchNumber(height),
                )?;

                self.state_root = next_state_root;

                info!(
                    "New State Root after soft confirmation #{} is: {:?}",
                    height, self.state_root
                );

                self.storage_manager.finalize_l2(height)?;

                height += 1;
            }
        }
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &Stf::StateRoot {
        &self.state_root
    }
}
