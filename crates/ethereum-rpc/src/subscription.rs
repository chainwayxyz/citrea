use std::sync::Arc;
use std::time::Duration;

use alloy_rpc_types::{Block, BlockNumHash, BlockNumberOrTag, Filter, FilteredParams, Log};
use alloy_serde::WithOtherFields;
use citrea_evm::Evm;
use jsonrpsee::{SubscriptionMessage, SubscriptionSink};
use reth_rpc_eth_types::logs_utils::log_matches_filter;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::WorkingSet;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const GC_TICK: Duration = Duration::from_secs(1);
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(1);

// We need a reference counted SubscriptionSink
//  because they remove uniq_sub on drop, so a simple clone would not work
//  to keep the subscription alive.
type SubSinkRc = Arc<SubscriptionSink>;

pub(crate) struct SubscriptionManager {
    l2_block_handle: JoinHandle<()>,
    logs_notifier_handle: JoinHandle<()>,
    heads_notifier_handle: JoinHandle<()>,
    gc_handle: JoinHandle<()>,
    head_subscriptions: Arc<RwLock<Vec<SubSinkRc>>>,
    logs_subscriptions: Arc<RwLock<Vec<(Filter, SubSinkRc)>>>,
}

impl SubscriptionManager {
    pub(crate) fn new<C: sov_modules_api::Context>(
        storage: C::Storage,
        ledger_db: LedgerDB,
        l2_block_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let (new_heads_tx, new_heads_rx) = mpsc::channel(16);
        let (logs_tx, logs_rx) = mpsc::channel(16);

        let head_subscriptions = Arc::new(RwLock::new(vec![]));
        let logs_subscriptions = Arc::new(RwLock::new(vec![]));

        let l2_block_rx = l2_block_rx;
        // Spawn the task that will listen for new l2 block heights
        // and send the corresponding ethereum block to subscribers
        let l2_block_handle = tokio::spawn(l2_block_event_handler::<C>(
            storage,
            ledger_db,
            l2_block_rx,
            new_heads_tx.clone(),
            logs_tx.clone(),
        ));

        let logs_notifier_handle = tokio::spawn(logs_notifier(logs_rx, logs_subscriptions.clone()));
        let heads_notifier_handle =
            tokio::spawn(new_heads_notifier(new_heads_rx, head_subscriptions.clone()));
        let gc_handle = tokio::spawn(collect_gc(
            head_subscriptions.clone(),
            logs_subscriptions.clone(),
        ));

        Self {
            l2_block_handle,
            logs_notifier_handle,
            heads_notifier_handle,
            gc_handle,
            head_subscriptions,
            logs_subscriptions,
        }
    }

    pub async fn register_new_heads_subscription(&self, subscription: SubscriptionSink) {
        let mut head_subscriptions = self.head_subscriptions.write().await;
        head_subscriptions.push(Arc::new(subscription));
    }

    pub async fn register_new_logs_subscription(
        &self,
        filter: Filter,
        subscription: SubscriptionSink,
    ) {
        let mut logs_subscriptions = self.logs_subscriptions.write().await;
        logs_subscriptions.push((filter, Arc::new(subscription)));
    }
}

impl Drop for SubscriptionManager {
    fn drop(&mut self) {
        self.gc_handle.abort();
        self.l2_block_handle.abort();
        self.logs_notifier_handle.abort();
        self.heads_notifier_handle.abort();
    }
}

async fn collect_gc(
    head_subscriptions: Arc<RwLock<Vec<SubSinkRc>>>,
    logs_subscriptions: Arc<RwLock<Vec<(Filter, SubSinkRc)>>>,
) {
    loop {
        tokio::time::sleep(GC_TICK).await;

        let mut head_subscriptions = head_subscriptions.write().await;
        head_subscriptions.retain(|s| !s.is_closed());
        drop(head_subscriptions);

        let mut logs_subscriptions = logs_subscriptions.write().await;
        logs_subscriptions.retain(|(_, s)| !s.is_closed());
        drop(logs_subscriptions);
    }
}

pub async fn new_heads_notifier(
    mut rx: mpsc::Receiver<WithOtherFields<Block>>,
    head_subscriptions: Arc<RwLock<Vec<SubSinkRc>>>,
) {
    while let Some(block) = rx.recv().await {
        debug!(target: "subscriptions", "Received new block: {}", block.header.number);
        // Acquire the read lock here to prevent starving the writes.
        let subscriptions = head_subscriptions.read().await;
        for subscription in subscriptions.iter() {
            let subscription = subscription.clone();
            let msg = SubscriptionMessage::new(
                subscription.method_name(),
                subscription.subscription_id(),
                &block,
            )
            .unwrap();
            tokio::spawn(async move {
                let _ = subscription.send_timeout(msg, SUBSCRIPTION_TIMEOUT).await;
            });
        }
        // Drop lock to release the read lock.
        drop(subscriptions);
    }
}

pub async fn logs_notifier(
    mut rx: mpsc::Receiver<Vec<Log>>,
    logs_subscriptions: Arc<RwLock<Vec<(Filter, SubSinkRc)>>>,
) {
    while let Some(logs) = rx.recv().await {
        // Acquire the read lock here to prevent starving the writes.
        let subscriptions = logs_subscriptions.read().await;
        for log in logs {
            for (filter, subscription) in subscriptions.iter().cloned() {
                let num_hash =
                    BlockNumHash::new(log.block_number.unwrap(), log.block_hash.unwrap());

                if log_matches_filter(num_hash, &log.inner, &FilteredParams::new(Some(filter))) {
                    let msg = SubscriptionMessage::new(
                        subscription.method_name(),
                        subscription.subscription_id(),
                        &log,
                    )
                    .unwrap();
                    tokio::spawn(async move {
                        let _ = subscription.send_timeout(msg, SUBSCRIPTION_TIMEOUT).await;
                    });
                }
            }
        }
        // Drop lock to release the read lock.
        drop(subscriptions);
    }
}

pub async fn l2_block_event_handler<C: sov_modules_api::Context>(
    storage: C::Storage,
    ledger_db: LedgerDB,
    mut l2_block_rx: broadcast::Receiver<u64>,
    new_heads_tx: mpsc::Sender<WithOtherFields<Block>>,
    logs_tx: mpsc::Sender<Vec<Log>>,
) {
    let evm = Evm::<C>::default();
    loop {
        let height = match l2_block_rx.recv().await {
            Err(RecvError::Lagged(n)) => {
                warn!(target: "subscriptions", "Lagged messages: {}", n);
                // Do not exit on lag
                continue;
            }
            Err(RecvError::Closed) => {
                warn!(target: "subscriptions", "l2_block_rx is closed");
                break;
            }
            Ok(height) => height,
        };

        let new_heads_tx = new_heads_tx.clone();
        let logs_tx = logs_tx.clone();

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

        tokio::spawn(async move {
            if let Err(_closed) = new_heads_tx.send(block).await {
                // Only possible error is no receiver
                warn!(target: "subscriptions", "new_heads_tx is closed");
            }
        });

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

        tokio::spawn(async move {
            if let Err(_closed) = logs_tx.send(logs).await {
                // Only possible error is no receiver
                warn!(target: "subscriptions", "logs_tx is closed");
            }
        });
    }
}
