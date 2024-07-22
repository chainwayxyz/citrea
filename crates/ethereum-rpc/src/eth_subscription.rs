use std::sync::Arc;

use jsonrpsee::types::ParamsSequence;
use jsonrpsee::PendingSubscriptionSink;
use sov_rollup_interface::services::da::DaService;

use crate::ethereum::Ethereum;

pub async fn handle_new_heads_subscription<C: sov_modules_api::Context, Da: DaService>(
    _params: ParamsSequence<'_>,
    _pending: PendingSubscriptionSink,
    _ethereum: Arc<Ethereum<C, Da>>,
) {
    unimplemented!()
}
