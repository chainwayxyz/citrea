use std::sync::Arc;

use citrea_evm::Evm;
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use reth_rpc_types::BlockNumberOrTag;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::services::da::DaService;

use crate::ethereum::Ethereum;

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
