use std::sync::Arc;

use citrea_evm::Evm;
use sov_db::ledger_db::SharedLedgerOps;
use sov_modules_api::Context;
use tokio::select;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Define pruning mode based on configuration and/or CLI arguments
pub enum PruningMode {
    /// Pruner does not run in this case.
    Archive,
    /// Pruner is run based on config.
    Pruned(PruningConfig),
}

/// A configuration type to define the behaviour of the pruner.
pub struct PruningConfig {
    /// Defines the number of blocks from the tip of the chain to remove.
    distance: u64,
}

pub struct Pruner<C, DB>
where
    C: Context,
    DB: SharedLedgerOps,
{
    /// config
    config: PruningConfig,
    /// A channel receiver which gets notified of new L2 blocks.
    receiver: broadcast::Receiver<u64>,
    /// Components to be pruned.
    evm: Arc<Evm<C>>,
    ledger_db: Arc<DB>,
}

impl<C, DB> Pruner<C, DB>
where
    C: Context,
    DB: SharedLedgerOps,
{
    /// Prune everything
    pub async fn prune(&self, up_to_block: u64) {
        self.prune_evm(up_to_block).await;
        self.prune_ledger(up_to_block).await;
    }

    /// Prune evm
    pub async fn prune_evm(&self, up_to_block: u64) {}

    /// Prune ledger
    pub async fn prune_ledger(&self, up_to_block: u64) {}

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                current_l2_block = self.receiver.recv() => {
                    if let Ok(current_l2_block) = current_l2_block {
                        self.prune(current_l2_block - self.config.distance).await;
                    }
                },
                _ = cancellation_token.cancelled() => {
                    return;
                }
            }
        }
    }
}
