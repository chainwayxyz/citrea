use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use jsonrpsee::core::client::SubscriptionClientT;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use parking_lot::Mutex;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_rollup_interface::rpc::MempoolTransactionSignal;
use tracing::{debug, error, info, instrument};

use crate::metrics::SEQUENCER_METRICS as SM;

/// MempoolSyncer is responsible for synchronizing the mempool transactions for listen mode sequencer
#[derive(Clone)]
pub struct MempoolSyncer<DB>
where
    DB: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// Database for ledger operations
    ledger_db: DB,
    /// Buffer for mempool transactions before storing into the ledger db
    /// Mapping: Tx hash to rlp encoded transaction
    transactions_buffer: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    /// Transaction hashes to be removed from mempool ledger db
    transactions_to_remove_buffer: Arc<Mutex<HashSet<Vec<u8>>>>,
    /// sequencer websocket endpoint
    sequencer_ws_endpoint: String,
}

impl<DB> MempoolSyncer<DB>
where
    DB: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new MempoolSyncer
    pub fn new(ledger_db: DB, sequencer_ws_endpoint: String) -> Self {
        SM.listen_mode_incoming_txs_to_be_removed_buffer_size
            .set(0.0);
        SM.listen_mode_incoming_txs_to_be_added_buffer_size.set(0.0);
        Self {
            ledger_db,
            transactions_buffer: Arc::new(Mutex::new(HashMap::new())),
            transactions_to_remove_buffer: Arc::new(Mutex::new(HashSet::new())),
            sequencer_ws_endpoint,
        }
    }

    #[instrument(name = "MempoolSyncer", skip_all)]
    pub async fn run(self, shutdown_signal: GracefulShutdown) {
        let this = self.clone();
        let subscription_shutdown_sig = shutdown_signal.clone();
        tokio::spawn(async move {
            // Start the subscription task
            this.run_subscription_task(subscription_shutdown_sig).await;
        });
        let update_mempool_shutdown_sig = shutdown_signal.clone();
        tokio::spawn(async move {
            // Start the update task
            self.update_mempool_transaction_db_task(update_mempool_shutdown_sig)
                .await;
        });

        let _ = shutdown_signal.await;
        info!("Shutting down mempool syncer");
    }

    /// Runs the subscription task for mempool transaction updates
    pub async fn run_subscription_task(&self, shutdown_signal: GracefulShutdown) {
        loop {
            let exponential_backoff = ExponentialBackoff::default();
            let _ = retry_backoff(exponential_backoff, || async {
                subscribe_to_mempool_transaction_updates(
                    &self.sequencer_ws_endpoint,
                    self.transactions_buffer.clone(),
                    self.transactions_to_remove_buffer.clone(),
                    shutdown_signal.clone(),
                )
                .await
                .map_err(|e| {
                    error!("Subscription error: {}", e);
                    backoff::Error::Transient {
                        err: e,
                        retry_after: None,
                    }
                })
            })
            .await;
        }
    }

    /// Runs the update task for mempool transaction database
    pub async fn update_mempool_transaction_db_task(&self, shutdown_signal: GracefulShutdown) {
        // Waiting at least 2 seconds here so that txs that got in block are removed so we do less db ops
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_signal.clone() => {
                    if let Err(e) = self.update_mempool_transactions() {
                        error!("Failed to update mempool transactions before shutdown: {}", e);
                    }
                    info!("Shutting down mempool transaction update task");
                    return;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.update_mempool_transactions() {
                        error!("Failed to update mempool transactions: {}", e);
                    }
                }
            }
        }
    }

    /// Updates the mempool transactions in the database
    fn update_mempool_transactions(&self) -> anyhow::Result<()> {
        let mut txs = self.transactions_buffer.lock().drain().collect::<Vec<_>>();
        SM.listen_mode_incoming_txs_to_be_added_buffer_size.set(0.0);

        let mut to_remove = {
            let mut guard = self.transactions_to_remove_buffer.lock();
            std::mem::take(&mut *guard)
        };
        SM.listen_mode_incoming_txs_to_be_removed_buffer_size
            .set(0.0);

        // If a tx is both in 'txs' and marked for removal, drop it from inserts
        // and consume it from the removal set so we don't try to remove it twice.
        txs.retain(|(h, _)| !to_remove.remove(h));

        if txs.is_empty() && to_remove.is_empty() {
            return Ok(());
        }

        if !txs.is_empty() {
            self.ledger_db.batch_insert_mempool_txs(txs)?;
        }

        if !to_remove.is_empty() {
            // Convert remaining set to a Vec only once at the edge
            let hashes: Vec<_> = to_remove.into_iter().collect();
            self.ledger_db.remove_mempool_txs(hashes)?;
        }

        Ok(())
    }
}

/// Subscribes to mempool transaction updates from the sequencer
async fn subscribe_to_mempool_transaction_updates(
    sequencer_ws_endpoint: &str,
    transactions_buffer: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    transactions_to_remove_buffer: Arc<Mutex<HashSet<Vec<u8>>>>,
    shutdown_signal: GracefulShutdown,
) -> anyhow::Result<()> {
    debug!(
        "Connecting to sequencer mempoolTransactions subscription at {}",
        sequencer_ws_endpoint
    );

    let ws_client = WsClientBuilder::default()
        .build(&sequencer_ws_endpoint)
        .await?;
    let mut subscription = ws_client
        .subscribe(
            "citrea_subscribe",
            rpc_params!["mempoolTransactions"],
            "citrea_unsubscribe",
        )
        .await?;

    loop {
        tokio::select! {
                _ = shutdown_signal.clone() => {
                    debug!("Shutting down mempool transaction subscription");
                    break;
                }
                Some(notification) = subscription.next() => {
                    match notification {
                        Ok(transaction_response) => match transaction_response {
                        MempoolTransactionSignal::NewTransaction((tx_hash, encoded_tx)) => {
                            debug!("New transaction received with hash: {:?}", tx_hash);
                            transactions_buffer
                                .lock()
                                .insert(tx_hash.to_vec(), encoded_tx);
                            SM.listen_mode_incoming_txs_to_be_added_buffer_size.increment(1);
                        }
                        MempoolTransactionSignal::RemoveTransactions(tx_hashes) => {
                            debug!("Removing transactions count: {:?}", tx_hashes.len());
                            let mut txs_to_remove_buffer = transactions_to_remove_buffer.lock();
                            txs_to_remove_buffer.extend(tx_hashes.iter().map(|tx_hash| tx_hash.to_vec()));
                            SM.listen_mode_incoming_txs_to_be_removed_buffer_size.increment(tx_hashes.len() as f64);
                        }
                        },
                        Err(e) => {
                            error!("Subscription notification error: {}", e);
                            return Err(e.into());
                        }
                    }
                }
        }
    }

    Ok(())
}
