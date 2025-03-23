use std::collections::VecDeque;
use std::sync::Arc;

use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, sync_l1};
use citrea_common::RollupPublicKeys;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::SlotNumber;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::{DaService, SlotData};
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::metrics::BATCH_PROVER_METRICS;

pub struct L1Syncer<Da, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
{
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pending_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    backup_manager: Arc<BackupManager>,
}

impl<Da, DB> L1Syncer<Da, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps + Clone + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_db: DB,
        da_service: Arc<Da>,
        public_keys: RollupPublicKeys,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
        backup_manager: Arc<BackupManager>,
    ) -> Self {
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            l1_block_cache,
            pending_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
        }
    }

    pub async fn run(mut self, start_l1_height: u64, cancellation_token: CancellationToken) {
        let l1_sync_worker = sync_l1(
            start_l1_height,
            self.da_service.clone(),
            self.pending_l1_blocks.clone(),
            self.l1_block_cache.clone(),
            BATCH_PROVER_METRICS.scan_l1_block.clone(),
        );
        tokio::pin!(l1_sync_worker);

        let backup_manager = self.backup_manager.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.tick().await;
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                _ = &mut l1_sync_worker => {},
                _ = interval.tick() => {
                    let _l1_guard = backup_manager.start_l1_processing().await;
                    if let Err(e) = self.process_l1_blocks().await {
                        error!("Could not process L1 blocks: {:?}", e);
                    }
                },
            }
        }
    }

    async fn process_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        let mut pending_l1_blocks = self.pending_l1_blocks.lock().await;

        while !pending_l1_blocks.is_empty() {
            let l1_block = pending_l1_blocks
                .front()
                .expect("Pending l1 blocks cannot be empty");
            let l1_height = l1_block.header().height();
            let l1_block_hash = l1_block.header().hash().into();

            // Set the l1 height of the l1 hash
            self.ledger_db
                .set_l1_height_of_l1_hash(l1_block_hash, l1_height)
                .unwrap();

            // Set short header proof
            let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
                Da::block_to_short_header_proof(l1_block.clone());
            self.ledger_db
                .put_short_header_proof_by_l1_hash(
                    &l1_block_hash,
                    borsh::to_vec(&short_header_proof)
                        .expect("Should serialize short header proof"),
                )
                .expect("Should save short header proof to ledger db");


            let sequencer_commitments =
                extract_sequencer_commitments::<Da>(self.da_service.clone(), l1_block, &self.sequencer_da_pub_key);

            // TODO: Make sure commitment indexes are sequential

            // Store commitments by index
            for commitment in sequencer_commitments.iter() {
                self.ledger_db
                    .put_commitment_by_index(commitment)
                    .expect("Should store commitment");
            }

            self.ledger_db
                .set_last_scanned_l1_height(SlotNumber(l1_height))
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to put prover last scanned l1 height in the ledger db: {}",
                        e
                    );
                });

            BATCH_PROVER_METRICS.current_l1_block.set(l1_height as f64);

            pending_l1_blocks.pop_front();
        }

        Ok(())
    }
}
