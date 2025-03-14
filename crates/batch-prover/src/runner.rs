use core::panic;

use citrea_common::l2::{L2BlockSignal, L2SyncWorker};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_rollup_interface::services::da::DaService;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::metrics::BATCH_PROVER_METRICS;

pub struct CitreaBatchProver<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone,
{
    ledger_db: DB,
    l2_sync_worker: Option<L2SyncWorker<DA, DB>>,
    l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
}

impl<DA, DB> CitreaBatchProver<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + 'static,
{
    pub fn new(
        ledger_db: DB,
        l2_sync_worker: L2SyncWorker<DA, DB>,
        l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ledger_db,
            l2_sync_worker: Some(l2_sync_worker),
            l2_signal_rx,
        })
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(mut self, cancellation_token: CancellationToken) -> anyhow::Result<()> {
        let mut l2_sync_worker = self
            .l2_sync_worker
            .take()
            .expect("L2 sync worker should be set");
        let worker = l2_sync_worker.run(cancellation_token.child_token());
        tokio::pin!(worker);

        loop {
            select! {
                _ = &mut worker => {},
                Some(l2_block) = self.l2_signal_rx.recv() => {
                    if let Some(state_diff) = l2_block.state_diff {
                        // Save state diff to ledger DB
                        self.ledger_db.set_l2_state_diff(
                            L2BlockNumber(l2_block.height),
                            state_diff,
                        )?;
                    }

                    BATCH_PROVER_METRICS.current_l2_block.set(l2_block.height as f64);
                    BATCH_PROVER_METRICS.process_l2_block.record(l2_block.process_duration);
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
