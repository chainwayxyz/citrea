use std::sync::Arc;
use std::time::Duration;

use alloy_rpc_types::{Block, BlockNumHash, BlockNumberOrTag, Filter, FilteredParams, Log};
use alloy_serde::WithOtherFields;
use citrea_evm::Evm;
use jsonrpsee::{SubscriptionMessage, SubscriptionSink};
use reth_rpc_eth_types::logs_utils::log_matches_filter;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::WorkingSet;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tracing::warn;

const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct SubscriptionManager {
    l2_block_handle: JoinHandle<()>,
    heads_tx: broadcast::Sender<Arc<WithOtherFields<Block>>>,
    logs_tx: broadcast::Sender<Arc<Vec<Log>>>,
}

impl SubscriptionManager {
    pub(crate) fn new<C: sov_modules_api::Context>(
        storage: C::Storage,
        ledger_db: LedgerDB,
        l2_block_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let (heads_tx, _) = broadcast::channel(16);
        let (logs_tx, _) = broadcast::channel(16);

        let l2_block_handle = tokio::spawn(l2_block_event_handler::<C>(
            storage,
            ledger_db,
            l2_block_rx,
            heads_tx.clone(),
            logs_tx.clone(),
        ));

        Self {
            l2_block_handle,
            heads_tx,
            logs_tx,
        }
    }

    pub fn register_new_heads_subscription(&self, subscription: SubscriptionSink) {
        let rx = self.heads_tx.subscribe();
        tokio::spawn(head_subscriber_task(rx, Arc::new(subscription)));
    }

    pub fn register_new_logs_subscription(&self, filter: Filter, subscription: SubscriptionSink) {
        let rx = self.logs_tx.subscribe();
        tokio::spawn(log_subscriber_task(rx, filter, Arc::new(subscription)));
    }
}

impl Drop for SubscriptionManager {
    fn drop(&mut self) {
        self.l2_block_handle.abort();
    }
}

async fn head_subscriber_task(
    mut rx: broadcast::Receiver<Arc<WithOtherFields<Block>>>,
    sink: Arc<SubscriptionSink>,
) {
    loop {
        tokio::select! {
            biased;
            _ = sink.closed() => {
                break;
            }
            maybe_block = rx.recv() => {
                match maybe_block {
                    Ok(block) => {
                        let msg = SubscriptionMessage::new(
                            sink.method_name(),
                            sink.subscription_id(),
                            block.as_ref(),
                        )
                        .unwrap();
                        if sink.send_timeout(msg, SUBSCRIPTION_TIMEOUT).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(target: "subscriptions", "head subscriber lagged by {} messages", n);
                        if sink.is_closed() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn log_subscriber_task(
    mut rx: broadcast::Receiver<Arc<Vec<Log>>>,
    filter: Filter,
    sink: Arc<SubscriptionSink>,
) {
    let filtered_params = FilteredParams::new(Some(filter));
    loop {
        tokio::select! {
            biased;
            _ = sink.closed() => {
                break;
            }
            maybe_logs = rx.recv() => {
                match maybe_logs {
                    Ok(logs) => {
                        for log in logs.iter() {
                            let num_hash =
                                BlockNumHash::new(log.block_number.unwrap(), log.block_hash.unwrap());

                            if log_matches_filter(num_hash, &log.inner, &filtered_params) {
                                let msg = SubscriptionMessage::new(
                                    sink.method_name(),
                                    sink.subscription_id(),
                                    log,
                                )
                                .unwrap();
                                if sink.send_timeout(msg, SUBSCRIPTION_TIMEOUT).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(target: "subscriptions", "log subscriber lagged by {} messages", n);
                        if sink.is_closed() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn l2_block_event_handler<C: sov_modules_api::Context>(
    storage: C::Storage,
    ledger_db: LedgerDB,
    mut l2_block_rx: broadcast::Receiver<u64>,
    heads_tx: broadcast::Sender<Arc<WithOtherFields<Block>>>,
    logs_tx: broadcast::Sender<Arc<Vec<Log>>>,
) {
    let evm = Evm::<C>::default();
    loop {
        let height = match l2_block_rx.recv().await {
            Err(RecvError::Lagged(n)) => {
                warn!(target: "subscriptions", "Lagged messages: {}", n);
                continue;
            }
            Err(RecvError::Closed) => {
                warn!(target: "subscriptions", "l2_block_rx is closed");
                break;
            }
            Ok(height) => height,
        };

        let mut working_set = WorkingSet::new(storage.clone());
        let block = evm
            .get_block_by_number(
                Some(BlockNumberOrTag::Number(height)),
                None,
                &mut working_set,
                &ledger_db,
            )
            .expect("Error querying block from evm")
            .expect("Received signal but evm block is not found");

        // Ignore send errors — just means no subscribers currently
        let _ = heads_tx.send(Arc::new(block));

        let mut working_set = WorkingSet::new(storage.clone());

        let logs = evm
            .get_logs_in_block_range(
                &mut working_set,
                &Filter::default(),
                height,
                height,
                usize::MAX,
            )
            .expect("Error getting logs in block range");

        let _ = logs_tx.send(Arc::new(logs));
    }
}
