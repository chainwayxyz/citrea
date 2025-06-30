use reth_tasks::shutdown::Shutdown;
use tokio::select;
use tokio::sync::mpsc::Receiver;
use tracing::info;

use super::Rollback;
use crate::types::StorageNodeType;

pub struct RollbackSignal {
    _current_l2_height: u64,
    target_l2: u64,
    target_l1: u64,
    last_sequencer_commitment_index: u32,
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
    pub async fn run(mut self, node_type: StorageNodeType, mut shutdown_signal: Shutdown) {
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    return;
                },
                Some(signal) = self.receiver.recv() => {
                    info!("Received signal to rollback to L2 {}, L1 {}", signal.target_l2, signal.target_l1);
                    if let Err(e) = self.rollback.execute(node_type, Some(signal.target_l2), Some(signal.target_l1), Some(signal.last_sequencer_commitment_index)).await {
                        panic!("Could not rollback blocks: {:?}", e);
                    }
                }
            }
        }
    }
}
