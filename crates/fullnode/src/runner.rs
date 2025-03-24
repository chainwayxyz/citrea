use sov_db::ledger_db::NodeLedgerOps;
use sov_rollup_interface::services::da::DaService;
use tokio::select;
use tokio_util::sync::CancellationToken;
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
    pub async fn run(mut self, cancellation_token: CancellationToken) -> anyhow::Result<()> {
        let l2_syncer = self.l2_syncer.run(cancellation_token.clone());
        tokio::pin!(l2_syncer);

        loop {
            select! {
                _ = &mut l2_syncer => {},
                _ = cancellation_token.cancelled() => {
                    info!("Shutting down fullnode");
                    break;
                },
            }
        }

        Ok(())
    }
}
