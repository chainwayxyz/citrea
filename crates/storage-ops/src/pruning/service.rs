use reth_tasks::shutdown::GracefulShutdown;
use tokio::select;
use tokio::sync::broadcast;
use tracing::{debug, error, instrument};

use super::types::StorageNodeType;
use super::Pruner;

pub struct PrunerService {
    pruner: Pruner,
    /// The last block number which was pruned.
    last_pruned_block: u64,
    /// A channel receiver which gets notified of new L2 blocks.
    l2_receiver: broadcast::Receiver<u64>,
}

impl PrunerService {
    pub fn new(
        pruner: Pruner,
        last_pruned_block: u64,
        l2_receiver: broadcast::Receiver<u64>,
    ) -> Self {
        Self {
            pruner,
            last_pruned_block,
            l2_receiver,
        }
    }

    #[instrument(name = "PrunerService", skip(self))]
    pub async fn run(mut self, node_type: StorageNodeType, mut shutdown_signal: GracefulShutdown) {
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    // Store the last pruned l2 height in ledger DB to be restored in the next initialization.
                    if let Err(e) = self.pruner.store_last_pruned_l2_height(self.last_pruned_block) {
                        error!("Failed to store last pruned L2 height {}: {:?}", self.last_pruned_block, e);
                    }
                    return;
                }
                current_l2_block = self.l2_receiver.recv() => {
                    if let Ok(current_l2_block) = current_l2_block {
                        debug!("Pruner received L2 {}, checking criteria", current_l2_block);
                        if let Some(up_to_block) = self.pruner.should_prune(self.last_pruned_block, current_l2_block) {
                            self.pruner.prune(node_type, up_to_block).await;
                            self.last_pruned_block = up_to_block;
                        }
                    }
                },
            }
        }
    }
}
