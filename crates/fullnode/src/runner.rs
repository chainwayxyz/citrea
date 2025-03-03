use citrea_common::l2::L2BlockSignal;
use sov_db::ledger_db::NodeLedgerOps;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument};

use crate::metrics::FULLNODE_METRICS;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<DB>
where
    DB: NodeLedgerOps + Clone,
{
    _ledger_db: DB,
    l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
}

impl<DB> CitreaFullnode<DB>
where
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_db: DB,
        l2_signal_rx: mpsc::Receiver<L2BlockSignal>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            _ledger_db: ledger_db,
            l2_signal_rx,
        })
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(mut self, cancellation_token: CancellationToken) -> anyhow::Result<()> {
        loop {
            select! {
                Some(l2_block) = self.l2_signal_rx.recv() => {
                    FULLNODE_METRICS.current_l2_block.set(l2_block.height as f64);
                    FULLNODE_METRICS.process_soft_confirmation.record(l2_block.process_duration);
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
