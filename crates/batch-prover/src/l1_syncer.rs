use std::collections::VecDeque;
use std::sync::Arc;

use citrea_common::backup::BackupManager;
use citrea_common::cache::L1BlockCache;
use citrea_common::da::{extract_sequencer_commitments, sync_l1};
use citrea_common::RollupPublicKeys;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::SlotNumber;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::{DaService, SlotData};
use tokio::select;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::metrics::BATCH_PROVER_METRICS;

pub struct L1Syncer<Da, DB>
where
    Da: DaService,
    DB: BatchProverLedgerOps,
{
    ledger_db: DB,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    scan_l1_start_height: u64,
    l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
    pending_l1_blocks: Arc<Mutex<VecDeque<<Da as DaService>::FilteredBlock>>>,
    backup_manager: Arc<BackupManager>,
    l1_signal_tx: mpsc::Sender<()>,
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
        scan_l1_start_height: u64,
        l1_block_cache: Arc<Mutex<L1BlockCache<Da>>>,
        backup_manager: Arc<BackupManager>,
        l1_signal_tx: mpsc::Sender<()>,
    ) -> Self {
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            scan_l1_start_height,
            l1_block_cache,
            pending_l1_blocks: Arc::new(Mutex::new(VecDeque::new())),
            backup_manager,
            l1_signal_tx,
        }
    }

    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        let l1_start_height = self
            .ledger_db
            .get_last_scanned_l1_height()
            .expect("Failed to get last scanned l1 height when starting l1 syncer")
            .map(|h| h.0)
            .unwrap_or(self.scan_l1_start_height);

        let l1_sync_worker = sync_l1(
            l1_start_height,
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
                _ = &mut shutdown_signal => {
                    info!("Shutting down L1 syncer");
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

    async fn process_l1_blocks(&mut self) -> Result<(), anyhow::Error> {
        let mut pending_l1_blocks = self.pending_l1_blocks.lock().await;
        // don't ping if no new l1 blocks
        let should_ping = pending_l1_blocks.len() > 0;

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

            // Set short header proof
            let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
                Da::block_to_short_header_proof(l1_block.clone());
            self.ledger_db
                .put_short_header_proof_by_l1_hash(
                    &l1_hash,
                    borsh::to_vec(&short_header_proof)
                        .expect("Should serialize short header proof"),
                )
                .expect("Should save short header proof to ledger db");

            // Extract sequencer commitments
            let l1_commitments = extract_sequencer_commitments::<Da>(
                self.da_service.clone(),
                l1_block,
                &self.sequencer_da_pub_key,
            );

            // Store commitments by index
            for commitment in l1_commitments.iter() {
                let index = commitment.index;
                if index == 0 {
                    error!("Got commitment with 0 index");
                    continue;
                }

                match self.ledger_db.get_commitment_by_index(index)? {
                    Some(db_commitment) => {
                        if commitment != &db_commitment {
                            error!("Found duplicate commitment index with different data\nDA: {:?}\nDB:{:?}", commitment, db_commitment);
                        } else {
                            warn!("Got commitment index {} that was already in db", index);
                        }
                    }
                    None => {
                        info!(
                            "Got commitment with index {} in L1 block {}",
                            index, l1_height
                        );

                        self.ledger_db
                            .put_commitment_by_index(commitment)
                            .expect("Should store commitment");
                        self.ledger_db
                            .put_commitment_index_by_l1(SlotNumber(l1_height), index)
                            .expect("Should put commitment index by l1");
                        self.ledger_db
                            .put_prover_pending_commitment(index)
                            .expect("Should set commitment status to pending");
                    }
                }
            }

            // Set last scanned l1 height
            self.ledger_db
                .set_last_scanned_l1_height(SlotNumber(l1_height))
                .expect("Should put prover last scanned l1 height");

            BATCH_PROVER_METRICS.current_l1_block.set(l1_height as f64);

            pending_l1_blocks.pop_front();
        }

        if should_ping {
            // signal that new l1 blocks are processed
            if let Err(e) = self.l1_signal_tx.try_send(()) {
                match e {
                    TrySendError::Closed(_) => error!("L1 signal receiver channel closed"),
                    TrySendError::Full(_) => warn!("L1 signal receiver channel full"),
                }
            }
        }

        Ok(())
    }
}
