use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::anyhow;
use futures::channel::mpsc::UnboundedReceiver;
use futures::StreamExt;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::StateDiff;
use sov_rollup_interface::da::{DaData, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, SenderWithNotifier};
use tokio::select;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use self::strategy::{CommitmentController, MinSoftConfirmations, StateDiffThreshold};
use crate::commitment::strategy::CommitmentStrategy;

mod strategy;

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
    ledger_db: Arc<Db>,
    da_service: Arc<Da>,
    soft_confirmation_rx: UnboundedReceiver<(u64, StateDiff)>,
    commitment_controller: CommitmentController,
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Send + Sync + 'static,
{
    pub fn new(
        ledger_db: Arc<Db>,
        da_service: Arc<Da>,
        min_soft_confirmations: u64,
        soft_confirmation_rx: UnboundedReceiver<(u64, StateDiff)>,
    ) -> Self {
        let commitment_controller = CommitmentController::new(vec![
            Box::new(MinSoftConfirmations::new(
                ledger_db.clone(),
                min_soft_confirmations,
            )),
            Box::new(StateDiffThreshold::new(ledger_db.clone())),
        ]);
        Self {
            ledger_db,
            da_service,
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
                        return;
                    };

                    let commitment_info = match self.commitment_controller.should_commit(height, state_diff) {
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

        // Clear state diff early
        self.ledger_db.set_state_diff(vec![])?;

        let soft_confirmation_hashes = self
            .ledger_db
            .get_soft_confirmation_range(&(l2_start..=l2_end))?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        let commitment = self.get_commitment(commitment_info, soft_confirmation_hashes)?;

        debug!("Sequencer: submitting commitment: {:?}", commitment);

        let da_data = DaData::SequencerCommitment(commitment.clone());
        let (notify, rx) = oneshot::channel();
        let request = SenderWithNotifier { da_data, notify };
        self.da_service
            .get_send_transaction_queue()
            .send(Some(request))
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
}
