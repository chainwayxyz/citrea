use std::collections::VecDeque;
use std::sync::Arc;

use borsh::BorshDeserialize;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::l2::{process_l2_block, sync_l2, ProcessL2BlockResult};
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;
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
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::metrics::BATCH_PROVER_METRICS;
use crate::{InitParams, RollupPublicKeys, RunnerConfig};

pub struct L2Syncer<DA, DB>
where
    DA: DaService,
    DB: BatchProverLedgerOps + Clone,
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
}

impl<DA, DB> L2Syncer<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new `L2Syncer`.
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
                                let remaining_l2s = l2_blocks.into_iter().skip(index);
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
        let l2_block_result = process_l2_block(
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

        let ProcessL2BlockResult {
            l2_height,
            l2_block_hash,
            state_root,
            state_diff,
            process_duration,
        } = l2_block_result;

        self.state_root = state_root;
        self.l2_block_hash = l2_block_hash;

        self.ledger_db
            .set_l2_state_diff(L2BlockNumber(l2_height), state_diff)?;

        // Only errors when there are no receivers
        let _ = self.l2_block_tx.send(l2_height);

        BATCH_PROVER_METRICS.current_l2_block.set(l2_height as f64);
        BATCH_PROVER_METRICS
            .process_l2_block
            .record(process_duration);

        Ok(())
    }
}
