use criteria::DistanceCriteria;
use futures::future;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::SharedLedgerOps;
use tokio::select;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::criteria::Criteria;
use crate::pruners::{prune_evm, prune_ledger};

mod criteria;
mod pruners;
#[cfg(test)]
mod tests;

/// A configuration type to define the behaviour of the pruner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PruningConfig {
    /// Defines the number of blocks from the tip of the chain to remove.
    pub distance: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self { distance: 256 }
    }
}

pub struct Pruner<DB>
where
    DB: SharedLedgerOps,
{
    /// The last block number which was pruned.
    last_pruned_block: u64,
    /// A channel receiver which gets notified of new L2 blocks.
    l2_receiver: broadcast::Receiver<u64>,
    /// Access to ledger tables.
    ledger_db: DB,
    /// Criteria to decide pruning
    criteria: Box<dyn Criteria + Send + Sync>,
}

impl<DB> Pruner<DB>
where
    DB: SharedLedgerOps + Send + Sync + Clone + 'static,
{
    pub fn new(
        config: PruningConfig,
        last_pruned_block: u64,
        l2_receiver: broadcast::Receiver<u64>,
        ledger_db: DB,
    ) -> Self {
        // distance is the only criteria implemented at the moment.
        let criteria = Box::new(DistanceCriteria {
            distance: config.distance,
        });
        Self {
            last_pruned_block,
            l2_receiver,
            ledger_db,
            criteria,
        }
    }

    /// Prune everything
    pub async fn prune(&self, up_to_block: u64) {
        info!("Pruning up to L2 block: {}", up_to_block);
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
                current_l2_block = self.l2_receiver.recv() => {
                    if let Ok(current_l2_block) = current_l2_block {
                        if let Some(up_to_block) = self.criteria.should_prune(self.last_pruned_block, current_l2_block) {
                            self.prune(up_to_block).await;
                            self.last_pruned_block = up_to_block;
                        }
                    }
                },
            }
        }
    }
}
