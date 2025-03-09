use tokio::select;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::Rollback;
use crate::pruning::types::StorageNodeType;

pub struct RollbackSignal {
    current_l2_height: u64,
    target_l2: u64,
    target_l1: u64,
    last_commitment_l2_height: u64,
}

pub struct RollbackService {
    rollback: Rollback,
    receiver: Receiver<RollbackSignal>,
}

impl RollbackService {
    pub fn new(rollback: Rollback, receiver: Receiver<RollbackSignal>) -> Self {
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
                Some(signal) = self.receiver.recv() => {
                    info!("Received signal to rollback to L2 {}, L1 {}", signal.target_l2, signal.target_l1);
                    if let Err(e) = self.rollback.execute(node_type, signal.current_l2_height, signal.target_l2, signal.target_l1, signal.last_commitment_l2_height).await {
                        panic!("Could not rollback blocks: {:?}", e);
                    }
                }
            }
        }
    }
}
