use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context as _};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::utils::{create_shutdown_signal, soft_confirmation_to_receipt};
use citrea_common::{RollupPublicKeys, RpcConfig, RunnerConfig};
use citrea_primitives::types::SoftConfirmationHash;
use citrea_pruning::{Pruner, PruningConfig};
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::server::{BatchRequestConfig, RpcServiceBuilder, ServerBuilder};
use jsonrpsee::RpcModule;
use sequencer_client::{GetSoftConfirmationResponse, SequencerClient};
use sov_db::ledger_db::NodeLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::{Context, SignedSoftConfirmation, Spec};
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::spec::SpecId;
pub use sov_rollup_interface::stf::BatchReceipt;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::{Zkvm, ZkvmHost};
use sov_stf_runner::InitVariant;
use tokio::select;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument};

use crate::da_block_handler::L1BlockHandler;

type StateRoot<ST, Da> = <ST as StateTransitionFunction<Da>>::StateRoot;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<Stf, Da, Vm, C, DB>
where
    Da: DaService,
    Vm: ZkvmHost + Zkvm,
    Stf: StateTransitionFunction<Da::Spec> + StfBlueprintTrait<C, Da::Spec>,
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>>,
    DB: NodeLedgerOps + Clone,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: Stf,
    storage_manager: ProverStorageManager<Da::Spec>,
    ledger_db: DB,
    state_root: StateRoot<Stf, Da::Spec>,
    batch_hash: SoftConfirmationHash,
    rpc_config: RpcConfig,
    sequencer_client: SequencerClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_da_pub_key: Vec<u8>,
    prover_da_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    include_tx_body: bool,
    code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager,
    soft_confirmation_tx: broadcast::Sender<u64>,
    pruning_config: Option<PruningConfig>,
    task_manager: TaskManager<()>,
}

impl<Stf, Da, Vm, C, DB> CitreaFullnode<Stf, Da, Vm, C, DB>
where
    Da: DaService<Error = anyhow::Error>,
    Vm: ZkvmHost + Zkvm,
    <Vm as Zkvm>::CodeCommitment: Send,
    Stf: StateTransitionFunction<
            Da::Spec,
            PreState = ProverStorage<SnapshotManager>,
            ChangeSet = ProverStorage<SnapshotManager>,
        > + StfBlueprintTrait<C, Da::Spec>,
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>> + Send + Sync,
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
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
        mut storage_manager: ProverStorageManager<Da::Spec>,
        init_variant: InitVariant<Stf, Da::Spec>,
        code_commitments_by_spec: HashMap<SpecId, Vm::CodeCommitment>,
        fork_manager: ForkManager,
        soft_confirmation_tx: broadcast::Sender<u64>,
        task_manager: TaskManager<()>,
    ) -> Result<Self, anyhow::Error> {
        let (prev_state_root, prev_batch_hash) = match init_variant {
            InitVariant::Initialized((state_root, batch_hash)) => {
                info!("Chain is already initialized. Skipping initialization. State root: {}. Previous soft confirmation hash: {}", hex::encode(state_root.as_ref()), hex::encode(batch_hash));
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

        info!("Starting L2 height: {}", start_l2_height);

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
            sync_blocks_count: runner_config.sync_blocks_count,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            fork_manager,
            soft_confirmation_tx,
            pruning_config: runner_config.pruning_config,
            task_manager,
        })
    }

    /// Starts a RPC server with provided rpc methods.
    pub async fn start_rpc_server(
        &mut self,
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
        let rpc_middleware = RpcServiceBuilder::new().layer_fn(citrea_common::rpc::Logger);

        self.task_manager
            .spawn(move |cancellation_token| async move {
                let server = ServerBuilder::default()
                    .max_connections(max_connections)
                    .max_subscriptions_per_connection(max_subscriptions_per_connection)
                    .max_request_body_size(max_request_body_size)
                    .max_response_body_size(max_response_body_size)
                    .set_batch_request_config(BatchRequestConfig::Limit(batch_requests_limit))
                    .set_http_middleware(middleware)
                    .set_rpc_middleware(rpc_middleware)
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
        let current_spec = self.fork_manager.active_fork().spec_id;
        let soft_confirmation_result = self.stf.apply_soft_confirmation(
            current_spec,
            self.sequencer_pub_key.as_slice(),
            // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1247): incorrect pre-state root in case of re-org
            &self.state_root,
            pre_state,
            Default::default(),
            Default::default(),
            current_l1_block.header(),
            &mut signed_soft_confirmation,
        )?;

        let next_state_root = soft_confirmation_result.state_root_transition.final_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        self.storage_manager
            .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        let tx_bodies = if self.include_tx_body {
            Some(signed_soft_confirmation.blobs().to_owned())
        } else {
            None
        };

        let receipt =
            soft_confirmation_to_receipt::<C, _, Da::Spec>(signed_soft_confirmation, current_spec);

        self.ledger_db
            .commit_soft_confirmation(next_state_root.as_ref(), receipt, tx_bodies)?;

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

        if let Some(config) = &self.pruning_config {
            let pruner = Pruner::<DB>::new(
                config.clone(),
                self.ledger_db.get_last_pruned_l2_height()?.unwrap_or(0),
                self.soft_confirmation_tx.subscribe(),
                self.ledger_db.clone(),
            );

            self.task_manager
                .spawn(|cancellation_token| pruner.run(cancellation_token));
        }

        let ledger_db = self.ledger_db.clone();
        let da_service = self.da_service.clone();
        let sequencer_pub_key = self.sequencer_pub_key.clone();
        let sequencer_da_pub_key = self.sequencer_da_pub_key.clone();
        let prover_da_pub_key = self.prover_da_pub_key.clone();
        let code_commitments_by_spec = self.code_commitments_by_spec.clone();
        let l1_block_cache = self.l1_block_cache.clone();

        self.task_manager
            .spawn(move |cancellation_token| async move {
                let l1_block_handler = L1BlockHandler::<C, Vm, Da, Stf::StateRoot, DB>::new(
                    ledger_db,
                    da_service,
                    sequencer_pub_key,
                    sequencer_da_pub_key,
                    prover_da_pub_key,
                    code_commitments_by_spec,
                    l1_block_cache.clone(),
                );
                l1_block_handler
                    .run(start_l1_height, cancellation_token)
                    .await
            });

        let (l2_tx, mut l2_rx) = mpsc::channel(1);
        let l2_sync_worker = sync_l2::<Da>(
            self.start_l2_height,
            self.sequencer_client.clone(),
            l2_tx,
            self.sync_blocks_count,
        );
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
                                break;
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
        let exponential_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .build();

        let inner_client = &sequencer_client;
        let soft_confirmations: Vec<GetSoftConfirmationResponse> =
            match retry_backoff(exponential_backoff.clone(), || async move {
                match inner_client
                    .get_soft_confirmation_range::<Da::Spec>(
                        l2_height..=l2_height + sync_blocks_count - 1,
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

        let mut soft_confirmations: Vec<(u64, GetSoftConfirmationResponse)> = (l2_height
            ..l2_height + soft_confirmations.len() as u64)
            .zip(soft_confirmations)
            .collect();

        l2_height += soft_confirmations.len() as u64;

        // Make sure soft confirmations are sorted for us to make sure they are processed
        // in the correct order.
        soft_confirmations.sort_by_key(|(height, _)| *height);

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
