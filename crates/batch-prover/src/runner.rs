use core::panic;

use citrea_common::l2::L2BlockSignal;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::SoftConfirmationNumber;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::metrics::BATCH_PROVER_METRICS;

pub struct CitreaBatchProver<DB>
where
    DB: BatchProverLedgerOps + Clone,
{
    ledger_db: DB,
    l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
}

impl<DB> CitreaBatchProver<DB>
where
    DB: BatchProverLedgerOps + Clone + 'static,
{
    pub fn new(
        ledger_db: DB,
        l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ledger_db,
            l2_signal_rx,
        })
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(mut self, cancellation_token: CancellationToken) -> anyhow::Result<()> {
        loop {
            select! {
                Some(l2_block) = self.l2_signal_rx.recv() => {
                    if let Some(state_diff) = l2_block.state_diff {
                        // Save state diff to ledger DB
                        self.ledger_db.set_l2_state_diff(
                            SoftConfirmationNumber(l2_block.height),
                            state_diff,
                        )?;
                    }

                    BATCH_PROVER_METRICS.current_l2_block.set(l2_block.height as f64);
                    BATCH_PROVER_METRICS.process_soft_confirmation.record(l2_block.process_duration);
                }
                _ = cancellation_token.cancelled() => {
                    info!("Shutting down fullnode");
                    self.l2_signal_rx.close();
                    break;
                },
            }
        }

        Ok(())
    }
}
