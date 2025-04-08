use core::panic;

use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_rollup_interface::services::da::DaService;
use tokio::select;
use tracing::{info, instrument};

use crate::l2_syncer::L2Syncer;

pub struct CitreaBatchProver<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone,
{
    l2_syncer: L2Syncer<DA, DB>,
}

impl<DA, DB> CitreaBatchProver<DA, DB>
where
    DA: DaService<Error = anyhow::Error>,
    DB: BatchProverLedgerOps + Clone + 'static,
{
    pub fn new(l2_syncer: L2Syncer<DA, DB>) -> Result<Self, anyhow::Error> {
        Ok(Self { l2_syncer })
    }

    #[instrument(level = "trace", skip_all, err)]
    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) -> anyhow::Result<()> {
        let l2_syncer = self.l2_syncer.run(shutdown_signal.clone());
        tokio::pin!(l2_syncer);

        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down batch prover");
                    break;
                },
                _ = &mut l2_syncer => {},
            }
        }

        Ok(())
    }
}
