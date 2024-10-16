use std::ops::RangeInclusive;

use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_rollup_interface::services::da::DaService;
use tokio::select;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

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
    ledger_db: Db,
    da_service: Da,
    soft_confirmation_rx: broadcast::Receiver<u64>,
    commitment_controller: CommitmentController,
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Clone + 'static,
{
    pub fn new(
        ledger_db: Db,
        da_service: Da,
        min_soft_confirmations: u64,
        soft_confirmation_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let commitment_controller = CommitmentController::new(vec![
            Box::new(MinSoftConfirmations {
                ledger_db: ledger_db.clone(),
                number: min_soft_confirmations,
            }),
            Box::new(StateDiffThreshold {}),
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
                height = self.soft_confirmation_rx.recv() => {
                    let Ok(height) = height else {
                        // An error is returned because the channel is either
                        // closed or lagged.
                        return;
                    };

                    match self.commitment_controller.should_commit() {
                        Ok(Some(commitment_info)) => {
                            self.commit(commitment_info);
                        },
                        Err(e) => {
                            error!("Error while checking commitment criteria: {:?}", e);
                        },
                        _ => {
                            continue;
                        }
                    }
                }
            }
        }
    }

    pub async fn commit(&self, commitment_info: CommitmentInfo) {}
}
