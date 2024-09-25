use citrea_evm::Evm;
use futures::future;
use sov_db::ledger_db::SharedLedgerOps;
use sov_modules_api::default_context::DefaultContext;
use tokio::select;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::error;

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
    pub distance: u64,
}

pub struct Pruner<DB>
where
    DB: SharedLedgerOps,
{
    /// config
    config: PruningConfig,
    /// The last block number which was pruned.
    last_pruned_block: u64,
    /// A channel receiver which gets notified of new L2 blocks.
    receiver: broadcast::Receiver<u64>,
    /// Access to ledger tables.
    ledger_db: DB,
}

impl<DB> Pruner<DB>
where
    DB: SharedLedgerOps + Send + Sync + Clone + 'static,
{
    pub fn new(
        config: PruningConfig,
        last_pruned_block: u64,
        receiver: broadcast::Receiver<u64>,
        ledger_db: DB,
    ) -> Self {
        Self {
            config,
            last_pruned_block,
            receiver,
            ledger_db,
        }
    }

    /// Prune everything
    pub async fn prune(&self, up_to_block: u64) {
        let ledger_db = self.ledger_db.clone();
        let ledger_pruning_handle =
            tokio::task::spawn_blocking(move || prune_ledger(ledger_db, up_to_block));
        let evm_pruning_handle = tokio::task::spawn_blocking(move || prune_evm(up_to_block));

        future::join_all([ledger_pruning_handle, evm_pruning_handle]).await;
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    // Store the last pruned l2 height in ledger DB to be restored in the next initialization.
                    if let Err(e) = self.ledger_db.set_last_pruned_l2_height(self.last_pruned_block) {
                        error!("Failed to store last pruned L2 height {}: {:?}", self.last_pruned_block, e);
                    }
                    return;
                }
                current_l2_block = self.receiver.recv() => {
                    if let Ok(current_l2_block) = current_l2_block {
                        // Calculate the block at which pruning would be triggered.
                        // This is allowing `self.config.distance` blocks to be produced before we
                        // decide to prune the previous `self.config.distance` blocks.
                        let trigger_block = (self.last_pruned_block + self.config.distance) + 1;
                        if current_l2_block >=trigger_block {
                            self.prune(current_l2_block - self.config.distance).await;
                            self.last_pruned_block += self.config.distance;
                        }
                    }
                },
            }
        }
    }
}

/// Prune evm
pub fn prune_evm(_up_to_block: u64) {
    let _evm = Evm::<DefaultContext>::default();
    unimplemented!()
}

/// Prune ledger
pub fn prune_ledger<DB: SharedLedgerOps>(_ledger_db: DB, _up_to_block: u64) {
    unimplemented!()
}
