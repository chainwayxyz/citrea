use std::collections::HashMap;
use std::sync::Arc;

use citrea_evm::{Evm, Filter, LogResponse};
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_rpc_types::{BlockNumberOrTag, RichBlock};
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::{broadcast, Mutex};

use crate::ethereum::Ethereum;

pub(crate) struct SubscriptionManager {
    new_heads_tx: broadcast::Sender<RichBlock>,
    logs_tx_by_filter: Arc<Mutex<HashMap<Filter, broadcast::Sender<LogResponse>>>>,
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

                if new_heads_tx.receiver_count() == 0 {
                    continue;
                }

                let mut working_set = WorkingSet::<C>::new(storage.clone());
                let block = evm
                    .get_block_by_number(
                        Some(BlockNumberOrTag::Number(height)),
                        None,
                        &mut working_set,
                    )
                    .expect("Error querying block from evm")
                    .expect("Received signal but evm block is not found");

                // Only possible error is no receiver
                let _ = new_heads_tx.send(block);
            }
        });

        manager
    }

    pub(crate) fn subscribe_new_heads(&self) -> broadcast::Receiver<RichBlock> {
        self.new_heads_tx.subscribe()
    }
}

pub async fn handle_new_heads_subscription<C: sov_modules_api::Context, Da: DaService>(
    pending: PendingSubscriptionSink,
    ethereum: Arc<Ethereum<C, Da>>,
) {
    let mut rx = ethereum
        .subscription_manager
        .as_ref()
        .unwrap()
        .subscribe_new_heads();
    let subscription = pending.accept().await.unwrap();
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
