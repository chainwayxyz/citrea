use std::sync::Arc;

use citrea_evm::Evm;
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_rpc_types::{BlockNumberOrTag, RichBlock};
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::broadcast;

use crate::ethereum::Ethereum;

pub(crate) struct SubscriptionManager<C: sov_modules_api::Context> {
    storage: C::Storage,
    new_heads_tx: broadcast::Sender<RichBlock>,
}

impl<C: sov_modules_api::Context> SubscriptionManager<C> {
    pub(crate) fn new(storage: C::Storage, soft_confirmation_rx: broadcast::Receiver<u64>) -> Self {
        let mut soft_confirmation_rx = soft_confirmation_rx;
        let storage_c = storage.clone();
        let new_heads_tx = broadcast::channel(16).0;
        let new_heads_tx_c = new_heads_tx.clone();
        // let new_heads_tx_c = new_heads_tx.clone();
        // Spawn the task that will listen for new soft confirmation heights
        // and send the corresponding ethereum block to subscribers
        tokio::spawn(async move {
            let evm = Evm::<C>::default();
            loop {
                let Ok(height) = soft_confirmation_rx.recv().await else {
                    return;
                };

                if new_heads_tx_c.receiver_count() == 0 {
                    continue;
                }

                let mut working_set = WorkingSet::<C>::new(storage_c.clone());
                let block = evm
                    .get_block_by_number(
                        Some(BlockNumberOrTag::Number(height)),
                        None,
                        &mut working_set,
                    )
                    .expect("Error querying block from evm")
                    .expect("Received signal but evm block is not found");

                // Only error is no receiver
                let _ = new_heads_tx_c.send(block);
            }
        });
        Self {
            storage,
            new_heads_tx,
        }
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
        .soft_confirmation_rx
        .as_ref()
        .unwrap()
        .resubscribe();
    let evm = Evm::<C>::default();
    let subscription = pending.accept().await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok(block_number) = rx.recv().await else {
                // Connection closed
                return;
            };
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());
            let block = evm
                .get_block_by_number(
                    Some(BlockNumberOrTag::Number(block_number)),
                    None,
                    &mut working_set,
                )
                .expect("Error querying block from evm")
                .expect("Received signal but evm block is not found");

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
