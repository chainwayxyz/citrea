use std::collections::HashMap;
use std::sync::Arc;

use citrea_evm::{Evm, Filter, LogResponse};
use jsonrpsee::{SubscriptionMessage, SubscriptionSink};
use reth_rpc_types::{BlockNumberOrTag, RichBlock};
use sov_modules_api::WorkingSet;
use tokio::sync::{broadcast, Mutex};

pub(crate) struct SubscriptionManager {
    new_heads_tx: broadcast::Sender<RichBlock>,
    logs_tx_by_filter: Arc<Mutex<HashMap<Filter, broadcast::Sender<Vec<LogResponse>>>>>,
}

impl SubscriptionManager {
    pub(crate) fn new<C: sov_modules_api::Context>(
        storage: C::Storage,
        soft_confirmation_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let new_heads_tx = broadcast::channel(16).0;
        let logs_tx_by_filter = Arc::new(Mutex::new(HashMap::new()));
        let manager = Self {
            new_heads_tx: new_heads_tx.clone(),
            logs_tx_by_filter: logs_tx_by_filter.clone(),
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

                {
                    let logs_tx_by_filter = logs_tx_by_filter.lock().await;
                    if new_heads_tx.receiver_count() == 0 && logs_tx_by_filter.is_empty() {
                        continue;
                    }
                }

                let block_number = BlockNumberOrTag::Number(height);

                let mut working_set = WorkingSet::<C>::new(storage.clone());
                let block = evm
                    .get_block_by_number(Some(block_number), None, &mut working_set)
                    .expect("Error querying block from evm")
                    .expect("Received signal but evm block is not found");

                // Only possible error is no receiver
                let _ = new_heads_tx.send(block.clone());

                // Prune filters that have no subscriptions
                let mut logs_tx_by_filter = logs_tx_by_filter.lock().await;
                logs_tx_by_filter.retain(|_, tx| tx.receiver_count() != 0);
                let logs_tx_by_filter = logs_tx_by_filter.clone();

                for (filter, logs_tx) in logs_tx_by_filter.iter() {
                    let logs = evm.eth_get_logs(filter.clone(), &mut working_set).unwrap();
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

    pub(crate) async fn subscribe_logs(
        &self,
        filter: Filter,
    ) -> broadcast::Receiver<Vec<LogResponse>> {
        let mut logs_tx_by_filter = self.logs_tx_by_filter.lock().await;
        let tx = logs_tx_by_filter
            .entry(filter)
            .or_insert_with(|| broadcast::channel(8).0);
        tx.subscribe()
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
) {
    tokio::spawn(async move {
        loop {
            let Ok(logs) = rx.recv().await else {
                // Connection closed
                return;
            };

            for log in logs {
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
    });
}
