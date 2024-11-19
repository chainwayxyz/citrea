use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, BlockHash, Transaction, Txid};
use bitcoincore_rpc::json::GetTransactionResult;
use bitcoincore_rpc::{Client, RpcApi};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::select;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use crate::service::FINALITY_DEPTH;
use crate::spec::utxo::UTXO;

const DEFAULT_CHECK_INTERVAL: u64 = 60;
const DEFAULT_HISTORY_LIMIT: usize = 1_000; // Keep track of last 1k txs
const DEFAULT_MAX_HISTORY_SIZE: usize = 200_000_000; // Default max monitored tx total size to 200mb

type BlockHeight = u64;
type Result<T> = std::result::Result<T, MonitorError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending {
        in_mempool: bool,
        base_fee: u64,
        timestamp: u64,
    },
    Confirmed {
        block_hash: BlockHash,
        block_height: BlockHeight,
        confirmations: u64,
    },
    Finalized {
        block_hash: BlockHash,
        block_height: BlockHeight,
        confirmations: u64,
    },
    Replaced {
        by_txid: Txid,
    },
    Evicted,
}

#[derive(Debug, Clone, Copy)]
pub enum MonitoredTxKind {
    Commit,
    Reveal,
    Cpfp,
}

#[derive(Debug, Clone)]
pub struct MonitoredTx {
    pub tx: Transaction,
    address: Option<Address<NetworkUnchecked>>,
    pub initial_broadcast: u64,
    pub initial_height: BlockHeight,
    last_checked: Instant,
    pub status: TxStatus,
    pub prev_txid: Option<Txid>, // Previous tx in chain
    pub next_txid: Option<Txid>, // Next tx in chain
    pub kind: MonitoredTxKind,
}

impl MonitoredTx {
    pub fn to_utxos(&self) -> Option<Vec<UTXO>> {
        let confirmations = match self.status {
            TxStatus::Pending { .. } => 0,
            TxStatus::Confirmed { confirmations, .. }
            | TxStatus::Finalized { confirmations, .. } => confirmations,
            _ => return None,
        };

        let tx_id = self.tx.compute_txid();
        Some(
            self.tx
                .output
                .iter()
                .enumerate()
                .map(|(vout, output)| UTXO {
                    tx_id,
                    vout: vout as u32,
                    address: self.address.clone(),
                    script_pubkey: output.script_pubkey.to_hex_string(),
                    amount: output.value.to_sat(),
                    confirmations: confirmations as u32,
                    spendable: true,
                    solvable: true,
                })
                .collect(),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChainState {
    current_height: BlockHeight,
    current_tip: Option<BlockHash>,
    recent_blocks: Vec<(BlockHash, BlockHeight)>,
}

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Transaction already monitored")]
    AlreadyMonitored,
    #[error("Transaction not found")]
    TxNotFound,
    #[error("BlockHash not found")]
    BlockHashNotFound,
    #[error("Previous transaction not monitored: {0}")]
    PrevTxNotMonitored(Txid),
    #[error("Invalid tx chain, odd number of txs")]
    OddNumberOfTxs,
    #[error(transparent)]
    BitcoinRpcError(#[from] bitcoincore_rpc::Error),
    #[error(transparent)]
    BitcoinEncodeError(#[from] bitcoin::consensus::encode::Error),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub check_interval: u64,
    pub history_limit: usize,
    pub max_history_size: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            history_limit: DEFAULT_HISTORY_LIMIT,
            max_history_size: DEFAULT_MAX_HISTORY_SIZE,
        }
    }
}

#[derive(Debug)]
pub struct MonitoringService {
    client: Arc<Client>,
    monitored_txs: RwLock<HashMap<Txid, MonitoredTx>>,
    chain_state: RwLock<ChainState>,
    config: MonitoringConfig,
    // Last tx in queue
    last_tx: Mutex<Option<Txid>>,
    // Keep track of total monitored transaction size
    // Only takes into account inner tx field from MonitoredTx
    total_size: AtomicUsize,
}

impl MonitoringService {
    pub fn new(client: Arc<Client>, config: Option<MonitoringConfig>) -> Self {
        Self {
            client,
            monitored_txs: RwLock::new(HashMap::new()),
            chain_state: RwLock::new(ChainState::default()),
            config: config.unwrap_or_default(),
            last_tx: Mutex::new(None),
            total_size: AtomicUsize::new(0),
        }
    }

    pub async fn restore(&self) -> Result<()> {
        self.initialize_chainstate().await?;
        self.restore_from_mempool().await
    }

    async fn initialize_chainstate(&self) -> Result<()> {
        let current_height = self.client.get_block_count().await?;
        let current_tip = self.client.get_best_block_hash().await?;

        let mut recent_blocks = Vec::with_capacity(FINALITY_DEPTH as usize);
        let mut current_hash: BlockHash;

        for height in (0..FINALITY_DEPTH).map(|i| current_height.saturating_sub(i)) {
            current_hash = self.client.get_block_hash(height).await?;
            recent_blocks.push((current_hash, height));
        }

        let mut chain_state = self.chain_state.write().await;
        *chain_state = ChainState {
            current_height,
            current_tip: Some(current_tip),
            recent_blocks,
        };

        Ok(())
    }

    async fn restore_from_mempool(&self) -> Result<()> {
        let mut unspent = self
            .client
            .list_unspent(None, Some(FINALITY_DEPTH as usize), None, None, None)
            .await?;

        unspent.sort_unstable_by_key(|utxo| {
            utxo.ancestor_count.unwrap_or(0) as i64 - utxo.confirmations as i64 - utxo.vout as i64
        });

        let txids = unspent.into_iter().map(|utxo| utxo.txid).collect();

        self.monitor_transaction_chain(txids).await
    }

    /// Run monitoring to keep track of TX status and chain re-orgs
    pub async fn run(self: Arc<Self>, token: CancellationToken) {
        let mut interval = interval(Duration::from_secs(self.config.check_interval));
        loop {
            select! {
                biased;
                _ = token.cancelled() => {
                    debug!("Monitoring service received shutdown signal");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.check_chain_state().await {
                        error!("Error checking chain state: {}", e);
                    }
                    if let Err(e) = self.check_transactions().await {
                        error!("Error checking transactions: {}", e);
                    }
                    self.prune_old_transactions().await;
                }
            }
        }
    }

    /// Monitor a chain of transactions (commit/reveal pairs and any intermediate chunks)
    /// The txids are expected to be in order: [commit1, reveal1, commit2, reveal2, ..., commitN, revealN]
    /// where intermediate pairs are chunks leading to the final commit/reveal pair
    #[instrument(level = "trace", skip(self))]
    pub async fn monitor_transaction_chain(&self, txids: Vec<Txid>) -> Result<()> {
        if txids.len() % 2 != 0 {
            return Err(MonitorError::OddNumberOfTxs);
        }

        let mut last_tx = *self.last_tx.lock().await;

        let mut txids_iter = txids.into_iter();
        while let (Some(commit_txid), Some(reveal_txid)) = (txids_iter.next(), txids_iter.next()) {
            self.monitor_transaction(
                commit_txid,
                last_tx,
                Some(reveal_txid),
                MonitoredTxKind::Commit,
            )
            .await?;

            self.monitor_transaction(
                reveal_txid,
                Some(commit_txid),
                None,
                MonitoredTxKind::Reveal,
            )
            .await?;

            last_tx = Some(reveal_txid)
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn monitor_transaction(
        &self,
        txid: Txid,
        prev_txid: Option<Txid>,
        next_txid: Option<Txid>,
        kind: MonitoredTxKind,
    ) -> Result<()> {
        {
            let monitored_txs = self.monitored_txs.read().await;
            if monitored_txs.contains_key(&txid) {
                return Err(MonitorError::AlreadyMonitored);
            }

            if let Some(prev_tx_id) = prev_txid {
                if !monitored_txs.contains_key(&prev_tx_id) {
                    return Err(MonitorError::PrevTxNotMonitored(prev_tx_id));
                }
            }
        }

        let current_height = self.client.get_block_count().await?;
        let tx_result = self.client.get_transaction(&txid, None).await?;
        let tx = tx_result.transaction()?;

        self.total_size.fetch_add(tx.total_size(), Ordering::SeqCst);

        let status = self.determine_tx_status(&tx_result).await?;
        let monitored_tx = MonitoredTx {
            tx,
            address: tx_result
                .details
                .first()
                .and_then(|detail| detail.address.clone()),
            initial_broadcast: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            initial_height: current_height,
            last_checked: Instant::now(),
            status,
            prev_txid,
            next_txid,
            kind,
        };

        self.monitored_txs.write().await.insert(txid, monitored_tx);
        *self.last_tx.lock().await = Some(txid);
        debug!("[monitor_transaction_chain] setting last_tx : {:?}", txid);

        Ok(())
    }

    // Replace a TX with a new RBF tx
    #[instrument(skip(self))]
    pub async fn replace_txid(&self, prev_txid: Txid, new_txid: Txid) -> Result<()> {
        let monitored_tx = self
            .monitored_txs
            .read()
            .await
            .get(&prev_txid)
            .ok_or(MonitorError::PrevTxNotMonitored(prev_txid))?
            .clone();

        let current_height = self.client.get_block_count().await?;
        let tx_result = self.client.get_transaction(&new_txid, None).await?;
        let tx = tx_result.transaction()?;
        self.total_size.fetch_add(tx.total_size(), Ordering::SeqCst);

        let status = self.determine_tx_status(&tx_result).await?;

        let new_tx = MonitoredTx {
            tx,
            address: tx_result
                .details
                .first()
                .and_then(|detail| detail.address.clone()),
            initial_broadcast: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            initial_height: current_height,
            last_checked: Instant::now(),
            status,
            kind: monitored_tx.kind,
            prev_txid: monitored_tx.prev_txid,
            next_txid: monitored_tx.next_txid,
        };

        {
            let mut monitored_txs = self.monitored_txs.write().await;
            if let Some(prev_tx) = monitored_txs.get_mut(&prev_txid) {
                prev_tx.status = TxStatus::Replaced { by_txid: new_txid };
            }
            monitored_txs.insert(new_txid, new_tx);
        }

        {
            let mut last_tx = self.last_tx.lock().await;
            if last_tx.as_ref() == Some(&prev_txid) {
                *last_tx = Some(new_txid);
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn check_chain_state(&self) -> Result<()> {
        let new_height = self.client.get_block_count().await?;
        let new_tip = self.client.get_best_block_hash().await?;

        let mut chain_state = self.chain_state.write().await;

        if new_tip != chain_state.current_tip.unwrap_or(BlockHash::all_zeros()) {
            let mut current_hash: BlockHash;
            let mut new_blocks = vec![(new_tip, new_height)];
            let mut reorg_detected = false;
            let mut reorg_depth = 0;

            for i in 1..=FINALITY_DEPTH {
                let height = new_height.saturating_sub(i);
                current_hash = self.client.get_block_hash(height).await?;
                new_blocks.push((current_hash, height));

                if let Some(pos) = chain_state
                    .recent_blocks
                    .iter()
                    .position(|&(hash, _)| hash == current_hash)
                {
                    if pos != i as usize {
                        reorg_detected = true;
                        reorg_depth = i;
                    }
                    break;
                }
            }

            if reorg_detected {
                // Handle transaction status updates due to reorg
                self.handle_reorg(reorg_depth).await?;
            }

            chain_state.current_height = new_height;
            chain_state.current_tip = Some(new_tip);
            chain_state.recent_blocks = new_blocks;
        }

        Ok(())
    }

    async fn handle_reorg(&self, depth: u64) -> Result<()> {
        let mut txs = self.monitored_txs.write().await;

        for (txid, tx) in txs.iter_mut() {
            if let TxStatus::Confirmed { confirmations, .. } = tx.status {
                if confirmations <= depth {
                    let tx_result = self.client.get_transaction(txid, None).await?;
                    tx.status = self.determine_tx_status(&tx_result).await?;

                    if let TxStatus::Pending { .. } = tx.status {
                        info!("Rebroadcasting tx {tx:?}");
                        let raw_tx = self.client.get_raw_transaction_hex(txid, None).await?;
                        self.client.send_raw_transaction(raw_tx).await?;
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn check_transactions(&self) -> Result<()> {
        let mut txs = self.monitored_txs.write().await;

        for (txid, monitored_tx) in txs.iter_mut() {
            match &monitored_tx.status {
                // Check non-finalized TXs
                TxStatus::Pending { .. }
                | TxStatus::Confirmed { .. }
                | TxStatus::Replaced { .. } => {
                    let tx_result = self.client.get_transaction(txid, None).await?;
                    let new_status = self.determine_tx_status(&tx_result).await?;

                    monitored_tx.status = new_status;
                }
                _ => {}
            }

            monitored_tx.last_checked = Instant::now();
        }

        Ok(())
    }

    async fn determine_tx_status(&self, tx_result: &GetTransactionResult) -> Result<TxStatus> {
        let confirmations = tx_result.info.confirmations as u64;
        let status = if confirmations > 0 {
            let block_hash = tx_result
                .info
                .blockhash
                .ok_or(MonitorError::BlockHashNotFound)?;
            let block_height = self
                .client
                .get_block_info(&block_hash)
                .await
                .map(|header| header.height as u64)
                .unwrap_or(0);

            if confirmations >= FINALITY_DEPTH {
                TxStatus::Finalized {
                    block_hash,
                    block_height,
                    confirmations,
                }
            } else {
                TxStatus::Confirmed {
                    block_hash,
                    block_height,
                    confirmations,
                }
            }
        } else {
            match self.client.get_mempool_entry(&tx_result.info.txid).await {
                Ok(entry) => {
                    let base_fee = entry.fees.base.to_sat();
                    TxStatus::Pending {
                        in_mempool: true,
                        base_fee,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    }
                }
                Err(_) => TxStatus::Evicted,
            }
        };
        Ok(status)
    }

    async fn prune_old_transactions(&self) {
        let mut txs = self.monitored_txs.write().await;
        let current_size = self.total_size.load(Ordering::SeqCst);

        if txs.len() > self.config.history_limit || current_size > self.config.max_history_size {
            let to_remove: Vec<_> = txs
                .iter()
                .filter(|(_, tx)| matches!(tx.status, TxStatus::Finalized { .. }))
                .map(|(txid, tx)| (*txid, tx.initial_broadcast))
                .collect();

            let mut to_remove = to_remove;
            to_remove.sort_by_key(|&(_, time)| time);

            for (txid, _) in to_remove {
                if txs.len() <= self.config.history_limit
                    && self.total_size.load(Ordering::SeqCst) <= self.config.max_history_size
                {
                    break;
                }

                if let Some(removed_tx) = txs.remove(&txid) {
                    let tx_size = removed_tx.tx.total_size();
                    self.total_size.fetch_sub(tx_size, Ordering::SeqCst);
                }
            }
        }
    }

    pub async fn get_tx_status(&self, txid: &Txid) -> Option<TxStatus> {
        self.get_monitored_tx(txid).await.map(|tx| tx.status)
    }

    pub async fn get_monitored_tx(&self, txid: &Txid) -> Option<MonitoredTx> {
        self.monitored_txs.read().await.get(txid).cloned()
    }

    pub async fn get_monitored_txs(&self) -> HashMap<Txid, MonitoredTx> {
        self.monitored_txs.read().await.clone()
    }

    pub async fn get_last_tx(&self) -> Option<(Txid, MonitoredTx)> {
        let last_txid = (*self.last_tx.lock().await)?;
        let tx = self.monitored_txs.read().await.get(&last_txid)?.to_owned();
        Some((last_txid, tx))
    }

    pub async fn set_next_tx(&self, txid: &Txid, next_txid: Txid) {
        let mut monitored_txs = self.monitored_txs.write().await;
        if let Some(parent) = monitored_txs.get_mut(txid) {
            parent.next_txid = Some(next_txid);
        }
    }
}
