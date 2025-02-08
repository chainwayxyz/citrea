use core::panic;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::utils::soft_confirmation_to_receipt;
use citrea_common::{InitParams, RollupPublicKeys, RunnerConfig};
use citrea_primitives::types::SoftConfirmationHash;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::{Context, SignedSoftConfirmation, SlotData, Spec};
use sov_modules_stf_blueprint::{Runtime, StfBlueprint};
use sov_prover_storage_manager::{ProverStorage, ProverStorageManager, SnapshotManager};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::SoftConfirmationResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::StorageRootHash;
use tokio::select;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use crate::metrics::BATCH_PROVER_METRICS;

pub(crate) type StfTransaction<C, Da, RT> =
    <StfBlueprint<C, Da, RT> as StateTransitionFunction<Da>>::Transaction;
pub(crate) type StfWitness<C, Da, RT> =
    <StfBlueprint<C, Da, RT> as StateTransitionFunction<Da>>::Witness;

pub struct CitreaBatchProver<C, Da, DB, RT>
where
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>>,
    Da: DaService,
    DB: BatchProverLedgerOps + Clone,
    RT: Runtime<C, Da::Spec>,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: StfBlueprint<C, Da::Spec, RT>,
    storage_manager: ProverStorageManager<Da::Spec>,
    ledger_db: DB,
    state_root: StorageRootHash,
    batch_hash: SoftConfirmationHash,
    sequencer_client: HttpClient,
    sequencer_pub_key: Vec<u8>,
    phantom: std::marker::PhantomData<C>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager<'static>,
    soft_confirmation_tx: broadcast::Sender<u64>,
}

impl<C, Da, DB, RT> CitreaBatchProver<C, Da, DB, RT>
where
    C: Context + Spec<Storage = ProverStorage<SnapshotManager>>,
    Da: DaService<Error = anyhow::Error> + Send + 'static,
    DB: BatchProverLedgerOps + Clone + 'static,
    RT: Runtime<C, Da::Spec>,
{
    /// Creates a new `StateTransitionRunner`.
    ///
    /// If a previous state root is provided, uses that as the starting point
    /// for execution. Otherwise, initializes the chain using the provided
    /// genesis config.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner_config: RunnerConfig,
        init_params: InitParams,
        stf: StfBlueprint<C, Da::Spec, RT>,
        public_keys: RollupPublicKeys,
        da_service: Arc<Da>,
        ledger_db: DB,
        storage_manager: ProverStorageManager<Da::Spec>,
        fork_manager: ForkManager<'static>,
        soft_confirmation_tx: broadcast::Sender<u64>,
    ) -> Result<Self, anyhow::Error> {
        // Last L1/L2 height before shutdown.
        let start_l2_height = ledger_db.get_head_soft_confirmation_height()?.unwrap_or(0) + 1;

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: init_params.state_root,
            batch_hash: init_params.batch_hash,
            sequencer_client: HttpClientBuilder::default()
                .build(runner_config.sequencer_client_url)?,
            sequencer_pub_key: public_keys.sequencer_public_key,
            phantom: std::marker::PhantomData,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            sync_blocks_count: runner_config.sync_blocks_count,
            fork_manager,
            soft_confirmation_tx,
        })
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), anyhow::Error> {
        // Create l2 sync worker task
        let (l2_tx, mut l2_rx) = mpsc::channel(1);

        let start_l2_height = self.start_l2_height;
        let sequencer_client = self.sequencer_client.clone();
        let sync_blocks_count = self.sync_blocks_count;

        let l2_sync_worker = sync_l2(start_l2_height, sequencer_client, l2_tx, sync_blocks_count);
        tokio::pin!(l2_sync_worker);

        // Store L2 blocks and make sure they are processed in order.
        // Otherwise, processing N+1 L2 block before N would emit prev_hash mismatch.
        let mut pending_l2_blocks = VecDeque::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        loop {
            select! {
                _ = &mut l2_sync_worker => {},
                Some(l2_blocks) = l2_rx.recv() => {
                    // While syncing, we'd like to process L2 blocks as they come without any delays.
                    // However, when an L2 block fails to process for whatever reason, we want to block this process
                    // and make sure that we start processing L2 blocks in queue.
                    if pending_l2_blocks.is_empty() {
                        for (index, l2_block) in l2_blocks.iter().enumerate() {
                            if let Err(e) = self.process_l2_block(l2_block).await {
                                error!("Could not process L2 block: {}", e);
                                // This block failed to process, add remaining L2 blocks to queue including this one.
                                let remaining_l2s = l2_blocks[index..].to_vec();
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
                    while let Some(l2_block) = pending_l2_blocks.front() {
                        match self.process_l2_block(l2_block).await {
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
                _ = cancellation_token.cancelled() => {
                    info!("Shutting down batch prover");
                    l2_rx.close();
                    return Ok(());
                },
            }
        }
    }

    async fn process_l2_block(
        &mut self,
        soft_confirmation: &SoftConfirmationResponse,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

        let l2_height = soft_confirmation.l2_height;

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

        let mut signed_soft_confirmation: SignedSoftConfirmation<StfTransaction<C, Da::Spec, RT>> =
            soft_confirmation
                .clone()
                .try_into()
                .context("Failed to parse transactions")?;
        // Register this new block with the fork manager to active
        // the new fork on the next block
        self.fork_manager.register_block(l2_height)?;

        let current_spec = self.fork_manager.active_fork().spec_id;
        let soft_confirmation_result = self.stf.apply_soft_confirmation(
            current_spec,
            self.sequencer_pub_key.as_slice(),
            &self.state_root,
            pre_state,
            Default::default(),
            Default::default(),
            current_l1_block.header(),
            &mut signed_soft_confirmation,
        )?;
        let txs_bodies = signed_soft_confirmation.blobs().to_owned();

        let next_state_root = soft_confirmation_result.state_root_transition.final_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        // Save state diff to ledger DB
        self.ledger_db.set_l2_state_diff(
            SoftConfirmationNumber(l2_height),
            soft_confirmation_result.state_diff,
        )?;

        // Save witnesses data to ledger db
        self.ledger_db.set_l2_witness(
            l2_height,
            &soft_confirmation_result.witness,
            &soft_confirmation_result.offchain_witness,
        )?;

        self.storage_manager
            .save_change_set_l2(l2_height, soft_confirmation_result.change_set)?;

        self.storage_manager.finalize_l2(l2_height)?;

        let receipt =
            soft_confirmation_to_receipt::<C, _, Da::Spec>(signed_soft_confirmation, current_spec);

        self.ledger_db.commit_soft_confirmation(
            next_state_root.as_ref(),
            receipt,
            Some(txs_bodies),
        )?;

        self.ledger_db.extend_l2_range_of_l1_slot(
            SlotNumber(current_l1_block.header().height()),
            SoftConfirmationNumber(l2_height),
        )?;

        // Only errors when there are no receivers
        let _ = self.soft_confirmation_tx.send(l2_height);

        self.state_root = next_state_root;
        self.batch_hash = soft_confirmation.hash;

        info!(
            "New State Root after soft confirmation #{} is: {:?}",
            l2_height, self.state_root
        );

        BATCH_PROVER_METRICS.current_l2_block.set(l2_height as f64);
        BATCH_PROVER_METRICS.process_soft_confirmation.record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &StorageRootHash {
        &self.state_root
    }
}

async fn sync_l2(
    start_l2_height: u64,
    sequencer_client: HttpClient,
    sender: mpsc::Sender<Vec<SoftConfirmationResponse>>,
    sync_blocks_count: u64,
) {
    let mut l2_height = start_l2_height;
    info!("Starting to sync from L2 height {}", l2_height);
    loop {
        let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .with_multiplier(1.5)
            .build();

        let inner_client = &sequencer_client;
        let soft_confirmations = match retry_backoff(exponential_backoff.clone(), || async move {
            let soft_confirmations = inner_client
                .get_soft_confirmation_range(
                    U64::from(l2_height),
                    U64::from(l2_height + sync_blocks_count - 1),
                )
                .await;

            match soft_confirmations {
                Ok(soft_confirmations) => {
                    Ok(soft_confirmations.into_iter().flatten().collect::<Vec<_>>())
                }
                Err(e) => match e {
                    JsonrpseeError::Transport(e) => {
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

        l2_height += soft_confirmations.len() as u64;

        if let Err(e) = sender.send(soft_confirmations).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}
