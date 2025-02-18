use tokio::select;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::Rollback;
use crate::pruning::types::StorageNodeType;

pub struct RollbackService {
    rollback: Rollback,
    receiver: Receiver<(u64, u64)>,
}

impl RollbackService {
    pub fn new(rollback: Rollback, receiver: Receiver<(u64, u64)>) -> Self {
        Self { rollback, receiver }
    }

    /// Run service to rollback when instructed to
    pub async fn run(mut self, node_type: StorageNodeType, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                },
                Some((current_l2_height, num_blocks)) = self.receiver.recv() => {
                    info!("Received signal to rollback {num_blocks} blocks");
                    if let Err(e) = self.rollback.execute(node_type, current_l2_height, num_blocks).await {
                        panic!("Could not rollback blocks: {:?}", e);
                    }
                }
            }
        }
    }
}
