//! DA block syncing for the sequencer
//!
//! This module is responsible for processing L1 blocks, extracting and storing
//! sequencer commitments for the sequencer in listen mode.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::bail;
use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, sync_l1};
use citrea_common::RollupPublicKeys;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::{DaService, SlotData};
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{error, info, instrument};

/// Handles L1 sync operations for the sequencer by tracking the finalized L1 blocks and
/// extracting the sequencer commitments from them.
///
/// This struct is responsible for:
/// - Synchronizing L1 blocks
/// - Processing sequencer commitments
/// - Maintaining block processing order
/// - Managing the backup state
/// - Storing commitments in CommitmentsByNumber table
pub struct L1Syncer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps,
{
    /// Database for ledger operations
    ledger_db: DB,
    /// Data availability service instance
    da_service: Arc<Da>,
    /// Sequencer's DA public key for verifying commitments
    sequencer_da_pub_key: Vec<u8>,
    /// The height from which to start scanning L1 blocks
    scan_l1_start_height: u64,
    /// Cache for L1 blocks to avoid redundant fetches
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    /// Queue of pending L1 blocks to be processed
    pending_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
}

impl<Da, DB> L1Syncer<Da, DB>
where
    Da: DaService,
    DB: SequencerLedgerOps + Clone + 'static,
{
    /// Creates a new instance of `SequencerL1Syncer`
    ///     
    /// # Arguments
    /// * `ledger_db` - The database instance to store L1 block data.
    /// * `da_service` - The DA service instance to fetch L1 blocks.
    /// * `public_keys` - The public keys used for distinguishing between different rollup participants.
    /// * `scan_l1_start_height` - The height from which to start scanning L1 blocks.
    /// * `l1_block_cache` - A cache for L1 blocks to avoid redundant fetches.
    /// * `backup_manager` - Manager for backup operations.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_db: DB,
        da_service: Arc<Da>,
        public_keys: RollupPublicKeys,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
        backup_manager: Arc<BackupManager>,
    ) -> anyhow::Result<Self> {
        // Get the starting height from the database, checking the highest slot number
        // in CommitmentsByNumber table
        let Some(scan_l1_start_height) = ledger_db.get_last_commitment_slot_number()?.map(|s| s.0)
        else {
            bail!("Could not fetch last scanned L1 commitment height")
        };

        Ok(Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            scan_l1_start_height,
            l1_block_cache,
            pending_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
        })
    }

    /// Runs the SequencerL1Syncer until shutdown is signaled
    ///
    /// This method continuously:
    /// 1. Fetches new L1 blocks from the DA Layer
    /// 2. Processes each block to update the local state
    /// 3. Handles any errors with exponential backoff
    /// 4. Maintains metrics about syncing progress
    #[instrument(name = "SequencerL1Syncer", skip_all)]
    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        let l1_sync_worker = sync_l1(
            self.scan_l1_start_height,
            self.da_service.clone(),
            self.pending_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            None,
        );
        tokio::pin!(l1_sync_worker);

        let backup_manager = self.backup_manager.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down Sequencer L1 syncer");
                    return;
                }
                _ = interval.tick() => {
                    let _l1_guard = backup_manager.start_l1_processing().await;
                    if let Err(e) = self.process_l1_blocks().await {
                        error!("Could not process L1 blocks: {:?}", e);
                    }
                },
                _ = &mut l1_sync_worker => {},
            }
        }
    }

    /// Processes L1 blocks waiting in the queue
    ///
    /// This method for each L1 block in the queue:
    /// 1. Records block height to hash mapping
    /// 2. Extracts sequencer commitments and stores them by slot number
    /// 3. Updates the CommitmentsByNumber table with found commitments
    async fn process_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        let mut pending_l1_blocks = self.pending_l1_blocks.lock().await;

        // process all the pending l1 blocks
        while !pending_l1_blocks.is_empty() {
            let l1_block = pending_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");
            let l1_height = l1_block.header().height();
            let l1_hash = l1_block.header().hash().into();

            // Set the l1 height of the l1 hash
            self.ledger_db
                .set_l1_height_of_l1_hash(l1_hash, l1_height)
                .unwrap();

            // Extract sequencer commitments
            let l1_commitments = extract_sequencer_commitments::<Da>(
                self.da_service.clone(),
                l1_block,
                &self.sequencer_da_pub_key,
            );

            // Store commitments in CommitmentsByNumber table
            for commitment in l1_commitments.iter() {
                info!(
                    "Found commitment with index {} in L1 block {}",
                    commitment.index, l1_height
                );

                // Update commitments on DA slot - this stores in CommitmentsByNumber
                self.ledger_db
                    .update_commitments_on_da_slot(l1_height, commitment.clone())
                    .expect("Should store commitment in CommitmentsByNumber");
            }

            pending_l1_blocks.pop_front();

            info!("Processed L1 block {}", l1_height);
        }

        Ok(())
    }
}
