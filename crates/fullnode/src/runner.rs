use citrea_common::l2::{L2BlockSignal, L2SyncWorker};
use sov_db::ledger_db::NodeLedgerOps;
use sov_rollup_interface::services::da::DaService;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::metrics::FULLNODE_METRICS;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: NodeLedgerOps + Clone,
{
    _ledger_db: DB,
    l2_sync_worker: Option<L2SyncWorker<DA, DB>>,
    l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
}

impl<DA, DB> CitreaFullnode<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_db: DB,
        l2_sync_worker: L2SyncWorker<DA, DB>,
        l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            _ledger_db: ledger_db,
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
        let worker = l2_sync_worker.run(cancellation_token.clone());
        tokio::pin!(worker);

        loop {
            select! {
                _ = &mut worker => {},
                Some(l2_block) = self.l2_signal_rx.recv() => {
                    FULLNODE_METRICS.current_l2_block.set(l2_block.height as f64);
                    FULLNODE_METRICS.process_l2_block.record(l2_block.process_duration);
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
