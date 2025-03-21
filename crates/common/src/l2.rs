use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use borsh::BorshDeserialize;
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::core::client::Error as JsonrpseeError;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sov_db::ledger_db::SharedLedgerOps;
use sov_keys::default_signature::K256PublicKey;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{L2Block, StateDiff};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use tokio::select;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::{sleep, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::backup::BackupManager;
use crate::cache::L1BlockCache;
use crate::utils::{compute_tx_hashes, decode_sov_tx_and_update_short_header_proofs};
use crate::{InitParams, RollupPublicKeys, RunnerConfig};

enum SyncError {
    ResponseOverLimit,
    Call(String),
    Connection(String),
    Unknown(String),
}

pub struct L2BlockSignal {
    pub height: u64,
    pub process_duration: f64,
    pub state_diff: Option<StateDiff>,
}

pub struct L2SyncWorker<DA, DB>
where
    DA: DaService,
    DB: SharedLedgerOps + Clone,
{
    start_l2_height: u64,
    da_service: Arc<DA>,
    stf: StfBlueprint<DefaultContext, DA::Spec, CitreaRuntime<DefaultContext, DA::Spec>>,
    storage_manager: ProverStorageManager,
    ledger_db: DB,
    state_root: StorageRootHash,
    l2_block_hash: L2BlockHash,
    sequencer_client: HttpClient,
    sequencer_pub_key: K256PublicKey,
    include_tx_body: bool,
    _l1_block_cache: Arc<Mutex<L1BlockCache<DA>>>,
    sync_blocks_count: u64,
    fork_manager: ForkManager<'static>,
    l2_block_tx: broadcast::Sender<u64>,
    backup_manager: Arc<BackupManager>,
    l2_signal_tx: mpsc::Sender<L2BlockSignal>,
}

impl<DA, DB> L2SyncWorker<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: SharedLedgerOps + Clone + Send + Sync + 'static,
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
        stf: StfBlueprint<DefaultContext, DA::Spec, CitreaRuntime<DefaultContext, DA::Spec>>,
        public_keys: RollupPublicKeys,
        da_service: Arc<DA>,
        ledger_db: DB,
        storage_manager: ProverStorageManager,
        fork_manager: ForkManager<'static>,
        l2_block_tx: broadcast::Sender<u64>,
        backup_manager: Arc<BackupManager>,
        l2_signal_tx: mpsc::Sender<L2BlockSignal>,
        include_tx_body: bool,
    ) -> Result<Self, anyhow::Error> {
        let start_l2_height = ledger_db.get_head_l2_block_height()?.unwrap_or(0) + 1;

        info!("Starting L2 height: {}", start_l2_height);

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: init_params.prev_state_root,
            l2_block_hash: init_params.prev_l2_block_hash,
            sequencer_client: HttpClientBuilder::default()
                .build(runner_config.sequencer_client_url)?,
            sequencer_pub_key: K256PublicKey::try_from_slice(&public_keys.sequencer_public_key)?,
            include_tx_body,
            sync_blocks_count: runner_config.sync_blocks_count,
            _l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            fork_manager,
            l2_block_tx,
            backup_manager,
            l2_signal_tx,
        })
    }

    /// Runs the rollup.
    pub async fn run(&mut self, cancellation_token: CancellationToken) {
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
                    info!("Shutting down L2 sync worker");
                    l2_rx.close();
                    return;
                },
            }
        }
    }

    async fn process_l2_block(
        &mut self,
        l2_block_response: &L2BlockResponse,
    ) -> anyhow::Result<()> {
        let start = Instant::now();

        let l2_height = l2_block_response.header.height.to();

        info!(
            "Running l2 block batch #{} with hash: 0x{}",
            l2_height,
            hex::encode(l2_block_response.header.hash),
        );

        if self.l2_block_hash != l2_block_response.header.prev_hash {
            bail!("Previous hash mismatch at height: {}", l2_height);
        }

        let pre_state = self.storage_manager.create_storage_for_next_l2_height();
        assert_eq!(
            pre_state.version(),
            l2_height,
            "Prover storage version is corrupted"
        );
        let tx_bodies = Some(
            l2_block_response
                .txs
                .clone()
                .into_iter()
                .map(|tx| tx.tx)
                .collect::<Vec<_>>(),
        );

        // Register this new block with the fork manager to active
        // the new fork on the next block.
        self.fork_manager.register_block(l2_height)?;
        let current_spec = self.fork_manager.active_fork().spec_id;

        let l2_block: L2Block = l2_block_response
            .clone()
            .try_into()
            .context("Failed to parse transactions")?;

        let l2_block_result = {
            // After Post fork2 we do not have the slot hash in l2 blocks we inspect the txs and get the slot hashes from set block infos

            // Then store the short header proofs of those blocks in the ledger db

            decode_sov_tx_and_update_short_header_proofs(
                l2_block_response,
                &self.ledger_db,
                self.da_service.clone(),
            )
            .await?;

            self.stf.apply_l2_block(
                current_spec,
                &self.sequencer_pub_key,
                &self.state_root,
                pre_state,
                None,
                None,
                Default::default(),
                Default::default(),
                &l2_block,
            )?
        };

        let next_state_root = l2_block_result.state_root_transition.final_root;
        // Check if post state root is the same as the one in the l2 block
        if next_state_root.as_ref().to_vec() != l2_block.state_root() {
            bail!("Post state root mismatch at height: {}", l2_height)
        }

        self.storage_manager
            .finalize_storage(l2_block_result.change_set);

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
        //     L2BlockNumber(l2_height),
        // )?;

        // Only errors when there are no receivers
        let _ = self.l2_block_tx.send(l2_height);

        self.state_root = next_state_root;
        self.l2_block_hash = l2_block_response.header.hash;

        info!(
            "New State Root after l2 block #{} is: 0x{}",
            l2_height,
            hex::encode(self.state_root)
        );

        let duration = Instant::now()
            .saturating_duration_since(start)
            .as_secs_f64();

        if let Err(e) = self
            .l2_signal_tx
            .send(L2BlockSignal {
                height: l2_height,
                process_duration: duration,
                state_diff: Some(l2_block_result.state_diff),
            })
            .await
        {
            error!("Failed to send L2 block signal: {:?}", e);
        }

        Ok(())
    }

    /// Allows to read current state root
    pub fn get_state_root(&self) -> &StorageRootHash {
        &self.state_root
    }
}

async fn sync_l2(
    mut start_l2_height: u64,
    sequencer_client: HttpClient,
    sender: mpsc::Sender<Vec<L2BlockResponse>>,
    sync_blocks_count: u64,
) {
    let mut current_sync_blocks_count = sync_blocks_count;

    info!("Starting to sync from L2 height {}", start_l2_height);
    loop {
        let end_l2_height = start_l2_height + current_sync_blocks_count - 1;

        let inner_client = &sequencer_client;
        let mut l2_blocks = match get_l2_blocks_range(inner_client, start_l2_height, end_l2_height)
            .await
        {
            Ok(l2_blocks) => {
                // request has succeeded, try to increase sync blocks back up until original
                current_sync_blocks_count *= 2;
                if current_sync_blocks_count > sync_blocks_count {
                    current_sync_blocks_count = sync_blocks_count;
                }
                l2_blocks
            }
            Err(e) => match e {
                SyncError::ResponseOverLimit => {
                    debug!("Sync response size over limit, retrying...");
                    current_sync_blocks_count /= 2;
                    if current_sync_blocks_count == 1 {
                        warn!("Very slow sync at 1 block/s");
                    } else if current_sync_blocks_count == 0 {
                        error!("L2 blocks are getting too big. It is recommended to increase response size");
                        // Stop the sync since we cannot fetch new soft confirmations.
                        return;
                    }
                    continue;
                }
                SyncError::Connection(e) => {
                    error!("L2 sync: RPC connection error: {:?}", e);
                    continue;
                }
                SyncError::Call(e) => {
                    error!("L2 sync: RPC call error: {:?}", e);
                    continue;
                }
                SyncError::Unknown(e) => {
                    error!("L2 sync: RPC unknown error: {:?}", e);
                    continue;
                }
            },
        };

        if l2_blocks.is_empty() {
            debug!(
                "L2 block: no batch at starting height {}, retrying...",
                start_l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        start_l2_height += l2_blocks.len() as u64;

        // Make sure L2 blocks are sorted for us to make sure they are processed
        // in the correct order.
        l2_blocks.sort_by_key(|l2_block| l2_block.header.height);

        if let Err(e) = sender.send(l2_blocks).await {
            error!("Could not notify about L2 block: {}", e);
        }
    }
}

async fn get_l2_blocks_range(
    sequencer_client: &HttpClient,
    start_l2_height: u64,
    end_l2_height: u64,
) -> Result<Vec<L2BlockResponse>, SyncError> {
    let inner_client = &sequencer_client;

    let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .with_multiplier(1.5)
        .build();

    retry_backoff(exponential_backoff, || async move {
        let l2_blocks = inner_client
            .get_l2_block_range(U64::from(start_l2_height), U64::from(end_l2_height))
            .await;
        match l2_blocks {
            Ok(l2_blocks) => Ok(l2_blocks.into_iter().flatten().collect::<Vec<_>>()),
            Err(e) => match e {
                JsonrpseeError::Call(e) => {
                    if e.message().eq("Response is too big") {
                        return Err(backoff::Error::Permanent(SyncError::ResponseOverLimit));
                    }
                    let error_msg = format!("L2 block: call error during RPC call: {:?}", e);
                    debug!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Call(error_msg),
                        retry_after: None,
                    })
                }
                JsonrpseeError::Transport(e) => {
                    let error_msg = format!("L2 block: connection error during RPC call: {:?}", e);
                    debug!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Connection(error_msg),
                        retry_after: None,
                    })
                }
                _ => Err(backoff::Error::Transient {
                    err: SyncError::Unknown(format!(
                        "L2 block: unknown error from RPC call: {:?}",
                        e
                    )),
                    retry_after: None,
                }),
            },
        }
    })
    .await
}
