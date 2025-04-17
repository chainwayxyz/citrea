use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::NodeLedgerOps;
use sov_rollup_interface::services::da::DaService;
use tracing::{info, instrument};

use crate::l2_syncer::L2Syncer;

/// Citrea's own STF runner implementation.
pub struct CitreaFullnode<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: NodeLedgerOps + Clone,
{
    l2_syncer: L2Syncer<DA, DB>,
}

impl<DA, DB> CitreaFullnode<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: NodeLedgerOps + Clone + Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(l2_syncer: L2Syncer<DA, DB>) -> Result<Self, anyhow::Error> {
        Ok(Self { l2_syncer })
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(mut self, shutdown_signal: GracefulShutdown) -> anyhow::Result<()> {
        self.l2_syncer.run(shutdown_signal).await;
        info!("Shutting down fullnode");

        Ok(())
    }
}
