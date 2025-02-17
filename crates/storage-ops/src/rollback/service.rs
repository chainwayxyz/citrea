use tokio::select;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::Rollback;

pub struct RollbackService {
    rollback: Rollback,
    receiver: Receiver<u32>,
}

impl RollbackService {
    pub fn new(rollback: Rollback, receiver: Receiver<u32>) -> Self {
        Self { rollback, receiver }
    }

    /// Run service to rollback when instructed to
    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                },
                Some(num_blocks) = self.receiver.recv() => {
                    info!("Received signal to rollback {num_blocks} blocks");
                    if let Err(e) = self.rollback.execute(num_blocks) {
                        panic!("Could not rollback blocks: {:?}", e);
                    }
                }
            }
        }
    }
}
