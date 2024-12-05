use core::panic;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::utils::create_shutdown_signal;
use citrea_common::{BatchProverConfig, RollupPublicKeys, RpcConfig, RunnerConfig};
use citrea_primitives::types::SoftConfirmationHash;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::server::{BatchRequestConfig, ServerBuilder};
use jsonrpsee::RpcModule;
use sequencer_client::{GetSoftConfirmationResponse, SequencerClient};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::storage::HierarchicalStorageManager;
use sov_modules_api::{Context, SignedSoftConfirmation, SlotData};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::ZkvmHost;
use sov_stf_runner::{InitVariant, ProverService};
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::sleep;
use tracing::{debug, error, info, instrument};

use crate::da_block_handler::L1BlockHandler;
use crate::rpc::{create_rpc_module, RpcContext};

type StateRoot<ST, Da> = <ST as StateTransitionFunction<Da>>::StateRoot;

pub struct CitreaBatchProver<C, Da, Sm, Vm, Stf, Ps, DB>
where
    C: Context,
    Da: DaService,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec> + StfBlueprintTrait<C, Da::Spec>,

    Ps: ProverService,
    DB: BatchProverLedgerOps + Clone,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: Stf,
    storage_manager: Sm,
    ledger_db: DB,
    state_root: StateRoot<Stf, Da::Spec>,
    batch_hash: SoftConfirmationHash,
    rpc_config: RpcConfig,
    prover_service: Arc<Ps>,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    prover_config: BatchProverConfig,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    elfs_by_spec: HashMap<SpecId, Vec<u8>>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager,
    soft_confirmation_tx: broadcast::Sender<u64>,
    task_manager: TaskManager<()>,
}

impl<C, Da, Sm, Vm, Stf, Ps, DB> CitreaBatchProver<C, Da, Sm, Vm, Stf, Ps, DB>
where
    C: Context,
    Da: DaService<Error = anyhow::Error> + Send + 'static,
    Sm: HierarchicalStorageManager<Da::Spec>,
    Vm: ZkvmHost + 'static,
    Stf: StateTransitionFunction<
            Da::Spec,
            PreState = Sm::NativeStorage,
            ChangeSet = Sm::NativeChangeSet,
        > + StfBlueprintTrait<C, Da::Spec>,
    Ps: ProverService<DaService = Da> + Send + Sync + 'static,
    DB: BatchProverLedgerOps + Clone + 'static,
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
        init_variant: InitVariant<Stf, Da::Spec>,
        prover_service: Arc<Ps>,
        prover_config: BatchProverConfig,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        elfs_by_spec: HashMap<SpecId, Vec<u8>>,
        fork_manager: ForkManager,
        soft_confirmation_tx: broadcast::Sender<u64>,
        task_manager: TaskManager<()>,
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
            elfs_by_spec,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            sync_blocks_count: runner_config.sync_blocks_count,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        })
    }

    /// Creates a shared RpcContext with all required data.
    #[allow(clippy::type_complexity)]
    fn create_rpc_context(
        &self,
    ) -> RpcContext<C, Da, Ps, Vm, DB, Stf::StateRoot, Stf::Witness, Stf::Transaction> {
        RpcContext {
            ledger: self.ledger_db.clone(),
            da_service: self.da_service.clone(),
            sequencer_da_pub_key: self.sequencer_da_pub_key.clone(),
            sequencer_pub_key: self.sequencer_pub_key.clone(),
            l1_block_cache: self.l1_block_cache.clone(),
            prover_service: self.prover_service.clone(),
            code_commitments_by_spec: self.code_commitments_by_spec.clone(),
            elfs_by_spec: self.elfs_by_spec.clone(),
            phantom_c: std::marker::PhantomData,
            phantom_vm: std::marker::PhantomData,
            phantom_sr: std::marker::PhantomData,
            phantom_w: std::marker::PhantomData,
            phantom_tx: std::marker::PhantomData,
        }
    }

    /// Updates the given RpcModule with Prover methods.
    pub fn register_rpc_methods(
        &self,
        mut rpc_methods: jsonrpsee::RpcModule<()>,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
        let rpc_context = self.create_rpc_context();
        let rpc = create_rpc_module(rpc_context);
        rpc_methods.merge(rpc)?;
        Ok(rpc_methods)
    }

    /// Starts a RPC server with provided rpc methods.
    pub async fn start_rpc_server(
        &mut self,
        methods: RpcModule<()>,
        channel: Option<oneshot::Sender<SocketAddr>>,
    ) -> anyhow::Result<()> {
        let methods = self.register_rpc_methods(methods)?;

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

        self.task_manager.spawn(|cancellation_token| async move {
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
                    cancellation_token.cancelled().await;
                }
                Err(e) => {
                    error!("Could not start RPC server: {}", e);
                }
            }
        });
        Ok(())
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

        let ledger_db = self.ledger_db.clone();
        let prover_config = self.prover_config.clone();
        let prover_service = self.prover_service.clone();
        let da_service = self.da_service.clone();
        let sequencer_pub_key = self.sequencer_pub_key.clone();
        let sequencer_da_pub_key = self.sequencer_da_pub_key.clone();
        let code_commitments_by_spec = self.code_commitments_by_spec.clone();
        let elfs_by_spec = self.elfs_by_spec.clone();
        let l1_block_cache = self.l1_block_cache.clone();

        self.task_manager.spawn(|cancellation_token| async move {
            let l1_block_handler = L1BlockHandler::<
                Vm,
                Da,
                Ps,
                DB,
                Stf::StateRoot,
                Stf::Witness,
                Stf::Transaction,
            >::new(
                prover_config,
                prover_service,
                ledger_db,
                da_service,
                sequencer_pub_key,
                sequencer_da_pub_key,
                code_commitments_by_spec,
                elfs_by_spec,
                skip_submission_until_l1,
                l1_block_cache.clone(),
            );
            l1_block_handler
                .run(start_l1_height, cancellation_token)
                .await
        });

        // Create l2 sync worker task
        let (l2_tx, mut l2_rx) = mpsc::channel(1);

        let start_l2_height = self.start_l2_height;
        let sequencer_client = self.sequencer_client.clone();
        let sync_blocks_count = self.sync_blocks_count;

        let l2_sync_worker =
            sync_l2::<Da>(start_l2_height, sequencer_client, l2_tx, sync_blocks_count);
        tokio::pin!(l2_sync_worker);

        // Store L2 blocks and make sure they are processed in order.
        // Otherwise, processing N+1 L2 block before N would emit prev_hash mismatch.
        let mut pending_l2_blocks: VecDeque<(u64, GetSoftConfirmationResponse)> = VecDeque::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        let mut shutdown_signal = create_shutdown_signal().await;

        loop {
            select! {
                _ = &mut l2_sync_worker => {},
                Some(l2_blocks) = l2_rx.recv() => {
                    // While syncing, we'd like to process L2 blocks as they come without any delays.
                    // However, when an L2 block fails to process for whatever reason, we want to block this process
                    // and make sure that we start processing L2 blocks in queue.
                    if pending_l2_blocks.is_empty() {
                        for (index, (l2_height, l2_block)) in l2_blocks.iter().enumerate() {
                            if let Err(e) = self.process_l2_block(*l2_height, l2_block).await {
                                error!("Could not process L2 block: {}", e);
                                // This block failed to process, add remaining L2 blocks to queue including this one.
                                let remaining_l2s: Vec<(u64, GetSoftConfirmationResponse)> = l2_blocks[index..].to_vec();
                                pending_l2_blocks.extend(remaining_l2s);
                            }
                        }
                        continue;
                    } else {
                        pending_l2_blocks.extend(l2_blocks);
                    }
                },
                _ = interval.tick() => {
                    if pending_l2_blocks.is_empty() {
                        continue;
                    }
                    while let Some((l2_height, l2_block)) = pending_l2_blocks.front() {
                        match self.process_l2_block(*l2_height, l2_block).await {
                            Ok(_) => {
                                pending_l2_blocks.pop_front();
                            },
                            Err(e) => {
                                error!("Could not process L2 block: {}", e);
                                // Get out of the while loop to go back to the outer one.
                                break;
                            }
                        }
                    }
                },
                Some(_) = shutdown_signal.recv() => return self.shutdown().await,
            }
        }
    }

    async fn shutdown(&self) -> anyhow::Result<()> {
        info!("Shutting down");
        self.task_manager.abort().await;
        Ok(())
    }

    async fn process_l2_block(
        &mut self,
        l2_height: u64,
        soft_confirmation: &GetSoftConfirmationResponse,
    ) -> anyhow::Result<()> {
        let current_l1_block = get_da_block_at_height(
            &self.da_service,
            soft_confirmation.da_slot_height,
            self.l1_block_cache.clone(),
        )
        .await?;

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

        let mut signed_soft_confirmation: SignedSoftConfirmation<Stf::Transaction> =
            soft_confirmation
                .clone()
                .try_into()
                .context("Failed to parse transactions")?;
        let soft_confirmation_result = self.stf.apply_soft_confirmation(
            self.fork_manager.active_fork().spec_id,
            self.sequencer_pub_key.as_slice(),
            // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
            &self.state_root,
            pre_state,
            Default::default(),
            Default::default(),
            current_l1_block.header(),
            &mut signed_soft_confirmation,
        )?;
        let txs_bodies = signed_soft_confirmation.blobs().to_owned();

        let receipt = soft_confirmation_result.soft_confirmation_receipt;

        let next_state_root = soft_confirmation_result.state_root_transition.final_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        // Save state diff to ledger DB
        self.ledger_db
            .set_l2_state_diff(BatchNumber(l2_height), soft_confirmation_result.state_diff)?;

        // Save witnesses data to ledger db
        self.ledger_db.set_l2_witness(
            l2_height,
            &soft_confirmation_result.witness,
            &soft_confirmation_result.offchain_witness,
        )?;

        self.storage_manager
            .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        self.ledger_db.commit_soft_confirmation(
            next_state_root.as_ref(),
            receipt,
            Some(txs_bodies),
        )?;

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

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &Stf::StateRoot {
        &self.state_root
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
                        l2_height..=l2_height + sync_blocks_count - 1,
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
