use sov_db::ledger_db::BatchProverLedgerOps;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::error;

pub struct Prover<DB>
where 
    DB: BatchProverLedgerOps,
{
    ledger_db: DB,
    l1_signal_rx: mpsc::Receiver<()>,
    l2_block_rx: broadcast::Receiver<u64>,
}

impl<DB> Prover<DB>
where 
    DB: BatchProverLedgerOps,
{
    pub fn new(ledger_db: DB, l1_signal_rx: mpsc::Receiver<()>, l2_block_rx: broadcast::Receiver<u64>) -> Self {
        Self {
            ledger_db,
            l1_signal_rx,
            l2_block_rx,
        }
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                l1_signal = self.l1_signal_rx.recv() => {
                    l1_signal.expect("L1 signal sender channel closed abruptly");

                    if let Err(e) = self.try_start_proving().await {
                        error!("Failed to start proving: {:?}", e);
                    }
                },
                l2_signal = self.l2_block_rx.recv() => {
                    l2_signal.expect("L2 signal sender channel closed abruptly");
                }
            }
        }
    }

    async fn try_start_proving(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
