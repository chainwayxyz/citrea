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
        tokio::spawn(async move {
            // Start the subscription task
            this.run_subscription_task().await;
        });

        tokio::spawn(async move {
            // Start the update task
            self.update_mempool_transaction_db_task().await;
        });

        let _ = shutdown_signal.await;
        info!("Shutting down mempool syncer");
    }

    pub async fn run_subscription_task(&self) {
        loop {
            let exponential_backoff = ExponentialBackoff::default();
            let _ = retry_backoff(exponential_backoff, || async {
                subscribe_to_mempool_transaction_updates(
                    &self.sequencer_ws_endpoint,
                    self.transactions_buffer.clone(),
                    self.transactions_to_remove_buffer.clone(),
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

    pub async fn update_mempool_transaction_db_task(&self) {
        loop {
            // Waiting at least 2 seconds here so that txs that got in block are removed so we do less db ops
            tokio::time::sleep(Duration::from_secs(3)).await;
            {
                let transactions_buffer = self.transactions_buffer.clone();
                let mut txs_buffer = transactions_buffer.lock();

                let txs = txs_buffer.drain().collect();
                if let Err(e) = self.ledger_db.batch_insert_mempool_txs(txs) {
                    error!("Failed to batch insert mempool transactions: {}", e);
                }
            }

            {
                let txs_to_remove_buffer = self.transactions_to_remove_buffer.clone();
                let mut txs_to_remove = txs_to_remove_buffer.lock();

                let txs = txs_to_remove.drain().collect();
                if let Err(e) = self.ledger_db.remove_mempool_txs(txs) {
                    error!("Failed to batch remove mempool transactions: {}", e);
                }
            }
        }
    }
}

async fn subscribe_to_mempool_transaction_updates(
    sequencer_ws_endpoint: &str,
    transactions_buffer: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    transactions_to_remove_buffer: Arc<Mutex<HashSet<Vec<u8>>>>,
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

    while let Some(notification) = subscription.next().await {
        match notification {
            Ok(transaction_response) => match transaction_response {
                MempoolTransactionSignal::NewTransaction((tx_hash, encoded_tx)) => {
                    debug!("New transaction received with hash: {:?}", tx_hash);
                    transactions_buffer
                        .lock()
                        .insert(tx_hash.to_vec(), encoded_tx);
                }
                MempoolTransactionSignal::RemoveTransactions(tx_hashes) => {
                    debug!("Removing transactions count: {:?}", tx_hashes.len());
                    let mut txs_to_remove_buffer = transactions_to_remove_buffer.lock();
                    txs_to_remove_buffer.extend(tx_hashes.iter().map(|tx_hash| tx_hash.to_vec()));
                }
            },
            Err(e) => {
                error!("Subscription notification error: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}
