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
    let mut rx = ethereum.soft_commitment_tx.subscribe();
    let evm = Evm::<C>::default();
    let subscription = pending.accept().await.unwrap();
    tokio::spawn(async move {
        loop {
            let block_number = rx.recv().await.unwrap();
            let mut working_set = WorkingSet::<C>::new(ethereum.storage.clone());
            let block = evm
                .get_block_by_number(
                    Some(BlockNumberOrTag::Number(block_number)),
                    None,
                    &mut working_set,
                )
                .unwrap()
                .unwrap();

            let msg = SubscriptionMessage::new(
                subscription.method_name(),
                subscription.subscription_id(),
                &block,
            )
            .unwrap();
            let _ = subscription.send(msg).await;
        }
    });
}
