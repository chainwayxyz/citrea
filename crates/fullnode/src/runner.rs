use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::get_da_block_at_height;
use citrea_common::utils::{compute_tx_hashes, decode_sov_tx_and_update_short_header_proofs};
use citrea_common::{InitParams, RollupPublicKeys, RunnerConfig};
use citrea_primitives::types::SoftConfirmationHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sov_db::ledger_db::NodeLedgerOps;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{L2Block, SpecId};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::SoftConfirmationResponse;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use tokio::select;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use crate::metrics::FULLNODE_METRICS;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<Da, DB>
where
    Da: DaService,
    DB: NodeLedgerOps + Clone,
{
    start_l2_height: u64,
    da_service: Arc<Da>,
    stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    storage_manager: ProverStorageManager,
    ledger_db: DB,
    state_root: StorageRootHash,
    soft_confirmation_hash: SoftConfirmationHash,
    sequencer_client: HttpClient,
    sequencer_pub_key: Vec<u8>,
    sequencer_k256_pub_key: Vec<u8>,
    include_tx_body: bool,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager<'static>,
    soft_confirmation_tx: broadcast::Sender<u64>,
    backup_manager: Arc<BackupManager>,
}

impl<Da, DB> CitreaFullnode<Da, DB>
where
    Da: DaService<Error = anyhow::Error>,
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
        init_params: InitParams,
        stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
        public_keys: RollupPublicKeys,
        da_service: Arc<Da>,
        ledger_db: DB,
        storage_manager: ProverStorageManager,
        fork_manager: ForkManager<'static>,
        soft_confirmation_tx: broadcast::Sender<u64>,
        backup_manager: Arc<BackupManager>,
    ) -> Result<Self, anyhow::Error> {
        let start_l2_height = ledger_db.get_head_soft_confirmation_height()?.unwrap_or(0) + 1;

        info!("Starting L2 height: {}", start_l2_height);

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: init_params.state_root,
            soft_confirmation_hash: init_params.batch_hash,
            sequencer_client: HttpClientBuilder::default()
                .build(runner_config.sequencer_client_url)?,
            sequencer_pub_key: public_keys.sequencer_public_key,
            sequencer_k256_pub_key: public_keys.sequencer_k256_public_key,
            include_tx_body: runner_config.include_tx_body,
            sync_blocks_count: runner_config.sync_blocks_count,
            l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            fork_manager,
            soft_confirmation_tx,
            backup_manager,
        })
    }

    async fn process_l2_block(
        &mut self,
        soft_confirmation: &SoftConfirmationResponse,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

        let l2_height = soft_confirmation.l2_height;

        info!(
            "Running soft confirmation batch #{} with hash: 0x{}",
            l2_height,
            hex::encode(soft_confirmation.hash)
        );

        if self.soft_confirmation_hash != soft_confirmation.prev_hash {
            bail!("Previous hash mismatch at height: {}", l2_height);
        }

        let pre_state = self.storage_manager.create_storage_for_next_l2_height();
        assert_eq!(
            pre_state.version(),
            l2_height,
            "Prover storage version is corrupted"
        );
        let tx_bodies = soft_confirmation
            .txs
            .clone()
            .map(|txs| txs.into_iter().map(|tx| tx.tx).collect::<Vec<_>>());

        // Register this new block with the fork manager to active
        // the new fork on the next block.
        self.fork_manager.register_block(l2_height)?;
        let current_spec = self.fork_manager.active_fork().spec_id;

        let l2_block: L2Block<Transaction> = soft_confirmation
            .clone()
            .try_into()
            .context("Failed to parse transactions")?;

        let sequencer_pub_key = if current_spec >= SpecId::Fork2 {
            self.sequencer_k256_pub_key.as_slice()
        } else {
            self.sequencer_pub_key.as_slice()
        };

        let soft_confirmation_result = if current_spec >= SpecId::Fork2 {
            // Since Post fork2 we do not have the slot hash in soft confirmations we inspect the txs and get the slot hashes from set block infos
            // Then store the short header proofs of those blocks in the ledger db
            decode_sov_tx_and_update_short_header_proofs(
                soft_confirmation,
                &self.ledger_db,
                self.da_service.clone(),
            )
            .await?;
            self.stf.apply_soft_confirmation(
                current_spec,
                sequencer_pub_key,
                &self.state_root,
                pre_state,
                None,
                None,
                Default::default(),
                Default::default(),
                &l2_block,
            )?
        } else {
            let current_l1_block = get_da_block_at_height(
                &self.da_service,
                soft_confirmation.da_slot_height, // THIS IS 0 AFTER FORK2
                self.l1_block_cache.clone(),
            )
            .await?;
            self.stf.apply_soft_confirmation_pre_fork2(
                current_spec,
                sequencer_pub_key,
                &self.state_root,
                pre_state,
                None,
                None,
                Default::default(),
                Default::default(),
                current_l1_block.header(),
                &l2_block,
            )?
        };

        let next_state_root = soft_confirmation_result.state_root_transition.final_root;
        // Check if post state root is the same as the one in the soft confirmation
        if next_state_root.as_ref().to_vec() != soft_confirmation.state_root {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        self.storage_manager
            .finalize_storage(soft_confirmation_result.change_set);

        let tx_hashes = compute_tx_hashes::<DefaultContext>(&l2_block.txs, current_spec);
        let tx_bodies = if self.include_tx_body {
            tx_bodies
        } else {
            None
        };

        self.ledger_db
            .commit_l2_block(l2_block, tx_hashes, tx_bodies)?;

        // TODO: https://github.com/chainwayxyz/citrea/issues/1992
        // self.ledger_db.extend_l2_range_of_l1_slot(
        //     SlotNumber(current_l1_block.header().height()),
        //     SoftConfirmationNumber(l2_height),
        // )?;

        // Only errors when there are no receivers
        let _ = self.soft_confirmation_tx.send(l2_height);

        self.state_root = next_state_root;
        self.soft_confirmation_hash = soft_confirmation.hash;

        info!(
            "New State Root after soft confirmation #{} is: 0x{}",
            l2_height,
            hex::encode(self.state_root)
        );

        FULLNODE_METRICS.current_l2_block.set(l2_height as f64);
        FULLNODE_METRICS.process_soft_confirmation.record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Runs the rollup.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), anyhow::Error> {
        let (l2_tx, mut l2_rx) = mpsc::channel(1);
        let l2_sync_worker = sync_l2(
            self.start_l2_height,
            self.sequencer_client.clone(),
            l2_tx,
            self.sync_blocks_count,
        );
        tokio::pin!(l2_sync_worker);

        // Store L2 blocks and make sure they are processed in order.
        // Otherwise, processing N+1 L2 block before N would emit prev_hash mismatch.
        let mut pending_l2_blocks = VecDeque::new();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;

        let backup_manager = self.backup_manager.clone();

        loop {
            select! {
                _ = &mut l2_sync_worker => {},
                Some(l2_blocks) = l2_rx.recv() => {
                    // While syncing, we'd like to process L2 blocks as they come without any delays.
                    // However, when an L2 block fails to process for whatever reason, we want to block this process
                    // and make sure that we start processing L2 blocks in queue.
                    if pending_l2_blocks.is_empty() {

                                for (index, l2_block) in l2_blocks.iter().enumerate() {
                            let _l2_lock = backup_manager.start_l2_processing().await;
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
                        let _l2_lock = backup_manager.start_l2_processing().await;
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
                    info!("Shutting down fullnode");
                    l2_rx.close();
                    return Ok(());
                },
            }
        }
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
        let exponential_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_secs(1))
            .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
            .with_multiplier(1.5)
            .build();

        let inner_client = &sequencer_client;
        let mut soft_confirmations = match retry_backoff(exponential_backoff, || async move {
            match inner_client
                .get_soft_confirmation_range(
                    U64::from(l2_height),
                    U64::from(l2_height + sync_blocks_count - 1),
                )
                .await
            {
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

        // Make sure soft confirmations are sorted for us to make sure they are processed
        // in the correct order.
        soft_confirmations.sort_by_key(|soft_confirmation| soft_confirmation.l2_height);

        if let Err(e) = sender.send(soft_confirmations).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}
