use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::anyhow;
use futures::channel::mpsc::UnboundedReceiver;
use futures::StreamExt;
use parking_lot::RwLock;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_modules_api::StateDiff;
use sov_rollup_interface::da::{BlockHeaderTrait, DaData, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SenderWithNotifier};
use tokio::select;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use self::controller::CommitmentController;

mod controller;

#[derive(Clone, Debug)]
pub struct CommitmentInfo {
    /// L2 heights to commit
    pub l2_height_range: RangeInclusive<BatchNumber>,
}

pub struct CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    soft_confirmation_rx: UnboundedReceiver<(u64, StateDiff)>,
    commitment_controller: Arc<RwLock<CommitmentController<Db>>>,
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(
        ledger_db: Db,
        da_service: Arc<Da>,
        sequencer_da_pub_key: Vec<u8>,
        min_soft_confirmations: u64,
        soft_confirmation_rx: UnboundedReceiver<(u64, StateDiff)>,
    ) -> Self {
        let commitment_controller = Arc::new(RwLock::new(CommitmentController::new(
            ledger_db.clone(),
            min_soft_confirmations,
        )));
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key,
            soft_confirmation_rx,
            commitment_controller,
        }
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                },
                info = self.soft_confirmation_rx.next() => {
                    let Some((height, state_diff)) = info else {
                        // An error is returned because the channel is either
                        // closed or lagged.
                        error!("Commitment service soft confirmation channel closed abruptly");
                        return;
                    };

                    let commitment_controller = self.commitment_controller.clone();

                    // Given that `should_commit` calls are blocking, as some strategies might
                    // decide to write to rocksdb, others might try to execute CPU-bound operations,
                    // we use `parking_lot::RwLock` here to lock the commitment controller inside
                    // the blocking thread so that we can execute these strategies.
                    let Ok(commitment_info) = tokio::task::spawn_blocking(move || {
                        commitment_controller.write().should_commit(height, state_diff)
                    }).await else {
                        error!("Could not decide on commitment. Blocking thread panicked");
                        continue;
                    };

                    let commitment_info = match commitment_info {
                        Ok(Some(commitment_info)) => {
                            commitment_info
                        },
                        Err(e) => {
                            error!("Error while checking commitment criteria: {:?}", e);
                            continue;
                        },
                        _ => {
                            continue;
                        }
                    };

                    if let Err(e) = self.commit(commitment_info, false).await {
                        error!("Could not submit commitment: {:?}", e);
                    }
                }
            }
        }
    }

    pub async fn commit(
        &self,
        commitment_info: CommitmentInfo,
        wait_for_da_response: bool,
    ) -> anyhow::Result<()> {
        let l2_start = *commitment_info.l2_height_range.start();
        let l2_end = *commitment_info.l2_height_range.end();

        let soft_confirmation_hashes = self
            .ledger_db
            .get_soft_confirmation_range(&(l2_start..=l2_end))?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        let commitment = self.get_commitment(commitment_info, soft_confirmation_hashes)?;

        debug!("Sequencer: submitting commitment: {:?}", commitment);

        let da_data = DaData::SequencerCommitment(commitment);
        let (notify, rx) = oneshot::channel();
        let request = SenderWithNotifier { da_data, notify };
        self.da_service
            .get_send_transaction_queue()
            .send(request)
            .map_err(|_| anyhow!("Bitcoin service already stopped!"))?;

        info!(
            "Sent commitment to DA queue. L2 range: #{}-{}",
            l2_start.0, l2_end.0,
        );

        let ledger_db = self.ledger_db.clone();
        let handle_da_response = async move {
            let result: anyhow::Result<()> = async move {
                let _tx_id = rx
                    .await
                    .map_err(|_| anyhow!("DA service is dead!"))?
                    .map_err(|_| anyhow!("Send transaction cannot fail"))?;

                ledger_db
                    .set_last_commitment_l2_height(l2_end)
                    .map_err(|_| {
                        anyhow!("Sequencer: Failed to set last sequencer commitment L2 height")
                    })?;

                ledger_db.delete_pending_commitment_l2_range(&(l2_start, l2_end))?;

                info!("New commitment. L2 range: #{}-{}", l2_start.0, l2_end.0);
                Ok(())
            }
            .await;

            if let Err(err) = result {
                error!(
                    "Error in spawned task for handling commitment result: {}",
                    err
                );
            }
        };

        if wait_for_da_response {
            // Handle DA response blocking
            handle_da_response.await;
        } else {
            // Add commitment to pending commitments
            self.ledger_db
                .put_pending_commitment_l2_range(&(l2_start, l2_end))?;

            // Handle DA response non-blocking
            tokio::spawn(handle_da_response);
        }
        Ok(())
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn resubmit_pending_commitments(&mut self) -> anyhow::Result<()> {
        info!("Resubmitting pending commitments");

        let pending_db_commitments = self.ledger_db.get_pending_commitments_l2_range()?;
        info!("Pending db commitments: {:?}", pending_db_commitments);

        let pending_mempool_commitments = self.get_pending_mempool_commitments().await;
        info!(
            "Commitments that are already in DA mempool: {:?}",
            pending_mempool_commitments
        );

        let last_commitment_l1_height = self
            .ledger_db
            .get_l1_height_of_last_commitment()?
            .unwrap_or(SlotNumber(1));
        let mined_commitments = self
            .get_mined_commitments_from(last_commitment_l1_height)
            .await?;
        info!(
            "Commitments that are already mined by DA: {:?}",
            mined_commitments
        );

        let mut pending_commitments_to_remove = vec![];
        pending_commitments_to_remove.extend(pending_mempool_commitments);
        pending_commitments_to_remove.extend(mined_commitments);

        for (l2_start, l2_end) in pending_db_commitments {
            if pending_commitments_to_remove.iter().any(|commitment| {
                commitment.l2_start_block_number == l2_start.0
                    && commitment.l2_end_block_number == l2_end.0
            }) {
                // Update last sequencer commitment l2 height
                match self.ledger_db.get_last_commitment_l2_height()? {
                    Some(last_commitment_l2_height) if last_commitment_l2_height >= l2_end => {}
                    _ => {
                        self.ledger_db.set_last_commitment_l2_height(l2_end)?;
                    }
                };

                // Delete from pending db if it is already in DA mempool or mined
                self.ledger_db
                    .delete_pending_commitment_l2_range(&(l2_start, l2_end))?;
            } else {
                // Submit commitment
                let commitment_info = CommitmentInfo {
                    l2_height_range: l2_start..=l2_end,
                };
                self.commit(commitment_info, true).await?;
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub fn get_commitment(
        &self,
        commitment_info: CommitmentInfo,
        soft_confirmation_hashes: Vec<[u8; 32]>,
    ) -> anyhow::Result<SequencerCommitment> {
        // sanity check
        assert_eq!(
            commitment_info.l2_height_range.end().0 - commitment_info.l2_height_range.start().0
                + 1u64,
            soft_confirmation_hashes.len() as u64,
            "Sequencer: Soft confirmation hashes length does not match the commitment info"
        );

        // build merkle tree over soft confirmations
        let merkle_root = MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice())
            .root()
            .ok_or(anyhow!("Couldn't compute merkle root"))?;
        Ok(SequencerCommitment {
            merkle_root,
            l2_start_block_number: commitment_info.l2_height_range.start().0,
            l2_end_block_number: commitment_info.l2_height_range.end().0,
        })
    }

    async fn get_pending_mempool_commitments(&self) -> Vec<SequencerCommitment> {
        self.da_service
            .get_pending_sequencer_commitments(&self.sequencer_da_pub_key)
            .await
    }

    async fn get_mined_commitments_from(
        &self,
        da_height: SlotNumber,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let head_da_height = self
            .da_service
            .get_head_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();
        let mut mined_commitments = vec![];
        for height in da_height.0..=head_da_height {
            let block = self
                .da_service
                .get_block_at(height)
                .await
                .map_err(|e| anyhow!(e))?;
            let iter = self
                .da_service
                .extract_relevant_sequencer_commitments(&block, &self.sequencer_da_pub_key)
                .unwrap_or_default();
            mined_commitments.extend(iter);
        }

        Ok(mined_commitments)
    }
}
