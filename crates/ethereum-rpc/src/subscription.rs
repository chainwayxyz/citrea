use citrea_evm::{log_matches_filter, Evm, Filter, LogResponse};
use jsonrpsee::{SubscriptionMessage, SubscriptionSink};
use reth_rpc_types::{BlockNumberOrTag, RichBlock};
use sov_modules_api::WorkingSet;
use tokio::sync::broadcast;

pub(crate) struct SubscriptionManager {
    new_heads_tx: broadcast::Sender<RichBlock>,
    logs_tx: broadcast::Sender<Vec<LogResponse>>,
}

impl SubscriptionManager {
    pub(crate) fn new<C: sov_modules_api::Context>(
        storage: C::Storage,
        soft_confirmation_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let new_heads_tx = broadcast::channel(16).0;
        let logs_tx = broadcast::channel(16).0;
        let manager = Self {
            new_heads_tx: new_heads_tx.clone(),
            logs_tx: logs_tx.clone(),
        };

        let mut soft_confirmation_rx = soft_confirmation_rx;
        // Spawn the task that will listen for new soft confirmation heights
        // and send the corresponding ethereum block to subscribers
        tokio::spawn(async move {
            let evm = Evm::<C>::default();
            loop {
                let Ok(height) = soft_confirmation_rx.recv().await else {
                    return;
                };

                let mut working_set = None;

                if new_heads_tx.receiver_count() != 0 {
                    working_set = Some(WorkingSet::<C>::new(storage.clone()));
                    let block = evm
                        .get_block_by_number(
                            Some(BlockNumberOrTag::Number(height)),
                            None,
                            working_set.as_mut().unwrap(),
                        )
                        .expect("Error querying block from evm")
                        .expect("Received signal but evm block is not found");

                    // Only possible error is no receiver
                    let _ = new_heads_tx.send(block.clone());
                }

                if logs_tx.receiver_count() != 0 {
                    let mut working_set =
                        working_set.unwrap_or_else(|| WorkingSet::<C>::new(storage.clone()));
                    let logs = evm
                        .get_logs_in_block_range(
                            &mut working_set,
                            &Filter::default(),
                            height,
                            height,
                        )
                        .expect("Error getting logs in block range");

                    // Only possible error is no receiver
                    let _ = logs_tx.send(logs);
                }
            }
        });

        manager
    }

    pub(crate) fn subscribe_new_heads(&self) -> broadcast::Receiver<RichBlock> {
        self.new_heads_tx.subscribe()
    }

    pub(crate) async fn subscribe_logs(&self) -> broadcast::Receiver<Vec<LogResponse>> {
        self.logs_tx.subscribe()
    }
}

pub async fn handle_new_heads_subscription(
    subscription: SubscriptionSink,
    mut rx: broadcast::Receiver<RichBlock>,
) {
    tokio::spawn(async move {
        loop {
            let Ok(block) = rx.recv().await else {
                // Connection closed
                return;
            };

            let msg = SubscriptionMessage::new(
                subscription.method_name(),
                subscription.subscription_id(),
                &block,
            )
            .unwrap();
            let Ok(_) = subscription.send(msg).await else {
                // Connection closed
                return;
            };
        }
    });
}

pub async fn handle_logs_subscription(
    subscription: SubscriptionSink,
    mut rx: broadcast::Receiver<Vec<LogResponse>>,
    filter: Filter,
) {
    tokio::spawn(async move {
        loop {
            let Ok(logs) = rx.recv().await else {
                // Connection closed
                return;
            };

            for log in logs {
                if log_matches_filter(
                    &log.clone().try_into().unwrap(),
                    &filter,
                    &filter.topics,
                    log.block_hash.as_ref().unwrap(),
                    &log.block_number.as_ref().unwrap().to::<u64>(),
                ) {
                    let msg = SubscriptionMessage::new(
                        subscription.method_name(),
                        subscription.subscription_id(),
                        &log,
                    )
                    .unwrap();
                    let Ok(_) = subscription.send(msg).await else {
                        // Connection closed
                        return;
                    };
                }
            }
        }
    });
}
