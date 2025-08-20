//! L2 block synchronization for the fullnode
//!
//! This module contains functionality for synchronizing L2 blocks from the sequencer
//! and processing them to maintain the fullnode's state.

use std::sync::Arc;

use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use borsh::BorshDeserialize;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::l2::{apply_l2_block, commit_l2_block, sync_l2};
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::SharedLedgerOps;
use sov_keys::default_signature::K256PublicKey;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::StorageRootHash;
use tokio::select;
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{error, info, instrument};

use crate::metrics::FULLNODE_METRICS;
use crate::{InitParams, RollupPublicKeys, RunnerConfig};

/// Component responsible for synchronizing and processing L2 blocks
///
/// The L2Syncer maintains the state of the L2 chain by:
/// - Fetching new blocks from the sequencer
/// - Validating block signatures and contents
/// - Processing blocks to update the local state
/// - Managing forks and state transitions
pub struct L2Syncer<DA, DB>
where
    DA: DaService,
    DB: SharedLedgerOps + Clone,
{
    /// Starting height for L2 block synchronization
    start_l2_height: u64,
    /// Data availability service instance
    da_service: Arc<DA>,
    /// State transition function blueprint
    stf: StfBlueprint<DefaultContext, DA::Spec, CitreaRuntime<DefaultContext, DA::Spec>>,
    /// Manager for prover storage
    storage_manager: ProverStorageManager,
    /// Database for ledger operations
    ledger_db: DB,
    /// Current state root hash
    state_root: StorageRootHash,
    /// Current L2 block hash
    l2_block_hash: L2BlockHash,
    /// HTTP client for connecting to the sequencer
    sequencer_client: HttpClient,
    /// Sequencer's public key for signature verification
    sequencer_pub_key: K256PublicKey,
    /// Whether to include transaction bodies in block storage
    include_tx_body: bool,
    /// Cache for L1 block data
    _l1_block_cache: Arc<Mutex<L1BlockCache<DA>>>,
    /// Number of blocks to sync at a time
    sync_blocks_count: u64,
    /// Manager for handling chain forks
    fork_manager: ForkManager<'static>,
    /// Channel for L2 block notifications
    l2_block_tx: broadcast::Sender<u64>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
}

impl<DA, DB> L2Syncer<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: SharedLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new L2Syncer instance
    ///
    /// # Arguments
    /// * `runner_config` - Configuration for the syncer
    /// * `init_params` - Initial parameters including previous state root and block hash
    /// * `stf` - State transition function blueprint
    /// * `public_keys` - Public keys for cryptographic operations
    /// * `da_service` - Data availability service
    /// * `ledger_db` - Database for ledger operations
    /// * `storage_manager` - Manager for prover storage
    /// * `fork_manager` - Manager for handling chain forks
    /// * `l2_block_tx` - Channel for L2 block notifications
    /// * `backup_manager` - Manager for backup operations
    /// * `include_tx_body` - Whether to include transaction bodies in block processing
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
        })
    }

    /// Runs the L2Syncer until shutdown is signaled
    ///
    /// This method continuously:
    /// 1. Fetches new L2 blocks from the sequencer
    /// 2. Processes each block to update the local state
    /// 3. Handles any errors with exponential backoff
    /// 4. Maintains metrics about syncing progress
    #[instrument(name = "L2Syncer", skip_all)]
    pub async fn run(&mut self, mut shutdown_signal: GracefulShutdown) {
        let (l2_tx, mut l2_rx) = mpsc::channel(1);
        let l2_sync_worker = sync_l2(
            self.start_l2_height,
            self.sequencer_client.clone(),
            l2_tx,
            self.sync_blocks_count,
        );
        tokio::pin!(l2_sync_worker);

        let backup_manager = self.backup_manager.clone();
        loop {
            select! {
                _ = &mut l2_sync_worker => {},
                Some(l2_blocks) = l2_rx.recv() => {
                    // While syncing, we'd like to process L2 blocks as they come without any delays.
                    for l2_block in l2_blocks {
                        let mut backoff = ExponentialBackoff::default();
                        loop {
                            let _l2_lock = backup_manager.start_l2_processing().await;
                            match self.process_l2_block(&l2_block).await {
                                Ok(_) => break,
                                Err(e) => {
                                    error!("Failed to process L2 block {}: {}", l2_block.header.height, e);
                                    let backoff_duration = backoff.next_backoff().expect("Failed to process L2 block multiple times. Killing L2Syncer...");
                                    tokio::time::sleep(backoff_duration).await;
                                }
                            }
                        }
                    }
                },
                _ = &mut shutdown_signal => {
                    info!("Shutting down L2 sync worker");
                    l2_rx.close();
                    return;
                },
            }
        }
    }

    /// Processes a single L2 block
    ///
    /// # Arguments
    /// * `l2_block_response` - Block data from the sequencer
    ///
    /// # Returns
    /// Success if the block was processed and state was updated, error otherwise
    async fn process_l2_block(
        &mut self,
        l2_block_response: &L2BlockResponse,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();

        let applied = apply_l2_block(
            l2_block_response,
            &self.storage_manager,
            &mut self.fork_manager,
            self.da_service.clone(),
            &self.ledger_db,
            &mut self.stf,
            self.l2_block_hash,
            self.state_root,
            &self.sequencer_pub_key,
            self.include_tx_body,
        )
        .await?;

        let l2_height = applied.l2_height;
        let state_root = applied.state_root;
        let block_size = applied.block_size;

        commit_l2_block(&self.ledger_db, applied)?;

        let process_duration = std::time::Instant::now()
            .saturating_duration_since(start)
            .as_secs_f64();

        self.state_root = state_root;
        self.l2_block_hash = l2_block_response.header.hash;

        // Only errors when there are no receivers
        let _ = self.l2_block_tx.send(l2_height);

        FULLNODE_METRICS.current_l2_block.set(l2_height as f64);
        FULLNODE_METRICS.process_l2_block.record(process_duration);
        FULLNODE_METRICS.l2_block_size.record(block_size as f64);

        Ok(())
    }
}
