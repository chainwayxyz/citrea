//! This module provides a monitoring service for Bitcoin transactions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, BlockHash, Transaction, Txid};
use bitcoincore_rpc::json::GetTransactionResult;
use bitcoincore_rpc::{Client, RpcApi};
use citrea_common::utils::read_env;
use citrea_common::FromEnv;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::shutdown::GracefulShutdown;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

use crate::helpers::builders::TxWithId;
use crate::helpers::parsers::parse_relevant_transaction;
use crate::spec::utxo::UTXO;

type BlockHeight = u64;
type Result<T> = std::result::Result<T, MonitorError>;

const REBROADCAST_EACH_N_BLOCK: u64 = 1;

/// Return UNIX timestamp in seconds
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Cannot fail because there is always a UNIX epoch")
        .as_secs()
}

/// Transaction status in the monitoring service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TxStatus {
    /// Queued tx, not already broadcasted
    Queued,
    /// Tx in mempool
    #[serde(rename_all = "camelCase")]
    InMempool {
        /// Base fee rate.
        base_fee: u64,
        /// Timestamp.
        timestamp: u64,
        /// Block height when transaction entered pool
        height: u64,
    },
    /// Tx confirmed but below finality_depth
    #[serde(rename_all = "camelCase")]
    Confirmed {
        /// Block hash where the tx was confirmed.
        block_hash: BlockHash,
        /// Block height where the tx was confirmed.
        block_height: u64,
        /// Number of confirmations.
        confirmations: u64,
    },
    /// Tx confirmed above finality_depth
    #[serde(rename_all = "camelCase")]
    Finalized {
        /// Block hash where the tx was confirmed.
        block_hash: BlockHash,
        /// Block height where the tx was confirmed.
        block_height: u64,
        /// Number of confirmations.
        confirmations: u64,
    },
    /// Tx replaced by RBF
    #[serde(rename_all = "camelCase")]
    Replaced {
        /// Txid of the transaction that replaced this one.
        by_txid: Txid,
    },
    /// Tx that was previously in mempool and not found anymore
    #[serde(rename_all = "camelCase")]
    Evicted {
        /// Last seen timestamp.
        last_seen: u64,
        /// Number of rebroadcast attempts.
        rebroadcast_attempts: u32,
        /// Last error message.
        last_error: Option<String>,
    },
}

/// The kind of transaction being monitored.
#[derive(Debug, Clone, Copy)]
pub enum MonitoredTxKind {
    /// Commit transaction, the first in a commit/reveal pair
    Commit,
    /// Reveal transaction, the second in a commit/reveal pair
    Reveal,
    /// Child-pays-for-parent transaction
    Cpfp,
}

/// A type for a monitored transaction with its metadata.
#[derive(Debug, Clone)]
pub struct MonitoredTx {
    pub(crate) tx: Transaction,
    pub(crate) txid: Txid,
    address: Option<Address<NetworkUnchecked>>,
    pub(crate) initial_broadcast: u64,
    pub(crate) initial_height: BlockHeight,
    last_checked: u64,
    pub(crate) status: TxStatus,
    /// Previous tx in the chain
    pub(crate) prev_txid: Option<Txid>,
    /// Next tx in the chain
    pub(crate) next_txid: Option<Txid>,
    pub(crate) kind: MonitoredTxKind,
}

impl MonitoredTx {
    /// Return the UTXOs for this transaction if it's not replaced or evicted.
    pub fn to_utxos(&self) -> Option<Vec<UTXO>> {
        let confirmations = match self.status {
            TxStatus::Queued | TxStatus::InMempool { .. } => 0,
            TxStatus::Confirmed { confirmations, .. }
            | TxStatus::Finalized { confirmations, .. } => confirmations,
            _ => return None,
        };

        Some(
            self.tx
                .output
                .iter()
                .enumerate()
                .map(|(vout, output)| UTXO {
                    tx_id: self.txid,
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

/// The state of the blockchain.
#[derive(Debug, Clone)]
pub struct ChainState {
    current_height: BlockHeight,
    current_tip: BlockHash,
    recent_blocks: Vec<(BlockHash, BlockHeight)>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            current_height: BlockHeight::default(),
            current_tip: BlockHash::all_zeros(),
            recent_blocks: Vec::new(),
        }
    }
}

/// Error types for the monitoring service.
#[derive(Error, Debug)]
pub enum MonitorError {
    /// Already monitored.
    #[error("Transaction already monitored")]
    AlreadyMonitored,
    /// Transaction not found.
    #[error("Transaction not found")]
    TxNotFound,
    /// BlockHash not set.
    #[error("BlockHash not set")]
    BlockHashNotSet,
    /// Previous transaction is not monitored.
    #[error("Previous transaction not monitored: {0}")]
    PrevTxNotMonitored(Txid),
    /// Invalid transaction chain, odd number of transactions.
    #[error("Invalid tx chain, odd number of txs")]
    OddNumberOfTxs,
    /// Transaction rebroadcast failed.
    #[error("Transaction rebroadcast failed: {0}")]
    RebroadcastFailed(String),
    /// RPC error.
    #[error(transparent)]
    BitcoinRpcError(#[from] bitcoincore_rpc::Error),
    #[error(transparent)]
    /// Bitcoin encoding error.
    BitcoinEncodeError(#[from] bitcoin::consensus::encode::Error),
    /// Other errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

mod monitoring_defaults {
    pub const fn check_interval() -> u64 {
        60
    }

    pub const fn history_limit() -> usize {
        1_000 // Keep track of last 1k txs
    }

    pub const fn max_history_size() -> usize {
        200_000_000 // Default max monitored tx total size to 200mb
    }

    pub const fn max_rebroadcast_attempts() -> u32 {
        15 // Maximum number of rebroadcast attempts for evicted txs
    }

    pub const fn rebroadcast_delay() -> u64 {
        300 // Wait 5 minutes between rebroadcast attempts
    }
}

/// Configuration for the monitoring service.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MonitoringConfig {
    /// Interval in seconds to check the chain state and transactions.
    #[serde(default = "monitoring_defaults::check_interval")]
    pub check_interval: u64,
    /// Limit on the number of historical transactions to keep track of.
    #[serde(default = "monitoring_defaults::history_limit")]
    pub history_limit: usize,
    /// Maximum size of the history in bytes.
    #[serde(default = "monitoring_defaults::max_history_size")]
    pub max_history_size: usize,
    /// Maximum number of rebroadcast attempts for evicted txs.
    #[serde(default = "monitoring_defaults::max_rebroadcast_attempts")]
    pub max_rebroadcast_attempts: u32,
    /// Delay between rebroadcast attempts.
    #[serde(default = "monitoring_defaults::rebroadcast_delay")]
    pub rebroadcast_delay: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: monitoring_defaults::check_interval(),
            history_limit: monitoring_defaults::history_limit(),
            max_history_size: monitoring_defaults::max_history_size(),
            max_rebroadcast_attempts: monitoring_defaults::max_rebroadcast_attempts(),
            rebroadcast_delay: monitoring_defaults::rebroadcast_delay(),
        }
    }
}

impl FromEnv for MonitoringConfig {
    fn from_env() -> anyhow::Result<Self> {
        match (
            read_env("DA_MONITORING_CHECK_INTERVAL"),
            read_env("DA_MONITORING_HISTORY_LIMIT"),
            read_env("DA_MONITORING_MAX_HISTORY_SIZE"),
            read_env("DA_MONITORING_MAX_REBROADCAST_ATTEMPTS"),
            read_env("DA_MONITORING_REBROADCAST_DELAY"),
        ) {
            (Err(_), Err(_), Err(_), Err(_), Err(_)) => Err(anyhow!("At least one of the monitoring envs must exist: DA_MONITORING_CHECK_INTERVAL, DA_MONITORING_HISTORY_LIMIT, DA_MONITORING_MAX_HISTORY_SIZE, DA_MONITORING_MAX_REBROADCAST_ATTEMPTS, DA_MONITORING_REBROADCAST_DELAY")),
            (check_interval, history_limit, max_history_size, max_rebroadcast_attempts, rebroadcast_delay) => Ok(MonitoringConfig {
                check_interval: check_interval.map_or_else(
                    |_| Ok(monitoring_defaults::check_interval()),
                    |v| v.parse().map_err(Into::<anyhow::Error>::into),
                )?,
                history_limit: history_limit.map_or_else(
                    |_| Ok(monitoring_defaults::history_limit()),
                    |v| v.parse().map_err(Into::<anyhow::Error>::into),
                )?,
                max_history_size: max_history_size.map_or_else(
                    |_| Ok(monitoring_defaults::max_history_size()),
                    |v| v.parse().map_err(Into::<anyhow::Error>::into),
                )?,
                max_rebroadcast_attempts: max_rebroadcast_attempts.map_or_else(
                    |_| Ok(monitoring_defaults::max_rebroadcast_attempts()),
                    |v| v.parse().map_err(Into::<anyhow::Error>::into),
                )?,
                rebroadcast_delay: rebroadcast_delay.map_or_else(
                    |_| Ok(monitoring_defaults::rebroadcast_delay()),
                    |v| v.parse().map_err(Into::<anyhow::Error>::into),
                )?,
            }),
        }
    }
}

/// Monitoring service for tracking transaction status and chain re-orgs.
/// It monitors commit/reveal transaction pairs, handles rebroadcasting of evicted transactions,
/// and maintains the chain state based on recent blocks.
#[derive(Debug)]
pub struct MonitoringService {
    client: Arc<Client>,
    monitored_txs: RwLock<HashMap<Txid, MonitoredTx>>,
    chain_state: RwLock<ChainState>,
    config: MonitoringConfig,
    // Last tx in queue
    last_tx: Mutex<Option<Txid>>,
    /// Keep track of total monitored transaction size
    /// Only takes into account inner tx field from MonitoredTx
    total_size: AtomicUsize,
    finality_depth: u64,
    block_tx: UnboundedSender<u64>,
}

impl MonitoringService {
    /// Creates a new instance of the MonitoringService
    pub fn new(
        client: Arc<Client>,
        config: Option<MonitoringConfig>,
        finality_depth: u64,
    ) -> (Self, UnboundedReceiver<u64>) {
        let (block_tx, block_rx) = tokio::sync::mpsc::unbounded_channel();

        (
            Self {
                client,
                monitored_txs: RwLock::new(HashMap::new()),
                chain_state: RwLock::new(ChainState::default()),
                config: config.unwrap_or_default(),
                last_tx: Mutex::new(None),
                total_size: AtomicUsize::new(0),
                finality_depth,
                block_tx,
            },
            block_rx,
        )
    }

    /// Restores the chain state and transaction monitoring from UTXOs
    pub async fn restore(&self) -> Result<()> {
        self.initialize_chainstate().await?;
        self.restore_from_utxos().await
    }

    async fn initialize_chainstate(&self) -> Result<()> {
        let current_height = self.client.get_block_count().await?;
        let current_tip = self.client.get_best_block_hash().await?;

        let mut recent_blocks = Vec::with_capacity(self.finality_depth as usize);
        let mut current_hash: BlockHash;

        for height in (0..self.finality_depth).map(|i| current_height.saturating_sub(i)) {
            current_hash = self.client.get_block_hash(height).await?;
            recent_blocks.push((current_hash, height));
        }

        let mut chain_state = self.chain_state.write().await;
        *chain_state = ChainState {
            current_height,
            current_tip,
            recent_blocks,
        };

        Ok(())
    }

    // Restore TX chain from utxos using list_unspent in range [0..self.finality_depth] confirmations
    async fn restore_from_utxos(&self) -> Result<()> {
        let mut unspent = self
            .client
            .list_unspent(None, Some(self.finality_depth as usize), None, None, None)
            .await?;

        unspent.sort_unstable_by_key(|utxo| {
            utxo.ancestor_count.unwrap_or(0) as i64 - utxo.confirmations as i64 - utxo.vout as i64
        });
        tracing::trace!("[restore_from_utxos] {unspent:?}");

        let mut txs = Vec::new();
        for tx in &unspent {
            let reveal_txid = tx.txid;
            let reveal_tx = self
                .client
                .get_transaction(&reveal_txid, None)
                .await?
                .transaction()
                .unwrap();

            let reveal_wtxid = reveal_tx.compute_wtxid();
            let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

            // Assumes that no wallet can hold both txs utxos
            if reveal_hash.starts_with(REVEAL_TX_PREFIX)
                && parse_relevant_transaction(&reveal_tx).is_ok()
            {
                let commit_txid = reveal_tx.input[0].previous_output.txid;
                let commit_tx = self
                    .client
                    .get_transaction(&commit_txid, None)
                    .await?
                    .transaction()
                    .unwrap();

                txs.push([
                    TxWithId {
                        id: commit_txid,
                        tx: commit_tx,
                    },
                    TxWithId {
                        id: reveal_txid,
                        tx: reveal_tx,
                    },
                ]);
            }
        }

        tracing::trace!("[restore_from_utxos] {txs:?}");

        self.monitor_transaction_chain(txs).await?;
        self.check_transactions().await
    }

    /// Run monitoring to keep track of TX status and chain re-orgs
    pub async fn run(self: Arc<Self>, mut shutdown_signal: GracefulShutdown) {
        let mut check_interval = interval(Duration::from_secs(self.config.check_interval));
        let mut evicted_interval = interval(Duration::from_secs(self.config.rebroadcast_delay));
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down monitoring service");
                    return;
                }
                _ = check_interval.tick() => {
                    if let Err(e) = self.check_chain_state().await {
                        error!("Error checking chain state: {}", e);
                    }
                    if let Err(e) = self.check_transactions().await {
                        error!("Error checking transactions: {}", e);
                    }
                    self.prune_old_transactions().await;
                }
                _ = evicted_interval.tick() => {
                    if let Err(e) = self.handle_evicted().await {
                        error!("Error handling evicted transactions: {}", e);
                    }
                }
            }
        }
    }

    /// Monitor a chain of transactions (commit/reveal pairs and any intermediate chunks)
    /// The txids are expected to be in order: [commit1, reveal1, commit2, reveal2, ..., commitN, revealN]
    /// where intermediate pairs are chunks leading to the final commit/reveal pair
    #[instrument(level = "trace", skip(self))]
    pub async fn monitor_transaction_chain(&self, txs: Vec<[TxWithId; 2]>) -> Result<()> {
        let mut last_tx = *self.last_tx.lock().await;

        for [commit, reveal] in txs {
            let next_id = reveal.id;
            let prev_id = commit.id;
            self.monitor_transaction(commit, last_tx, Some(next_id), MonitoredTxKind::Commit)
                .await?;

            self.monitor_transaction(reveal, Some(prev_id), None, MonitoredTxKind::Reveal)
                .await?;

            last_tx = Some(next_id)
        }

        Ok(())
    }

    /// Add a transaction to the monitoring service.
    #[instrument(skip(self))]
    pub async fn monitor_transaction(
        &self,
        tx: TxWithId,
        prev_txid: Option<Txid>,
        next_txid: Option<Txid>,
        kind: MonitoredTxKind,
    ) -> Result<()> {
        let txid = tx.id;

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

        self.total_size
            .fetch_add(tx.tx.total_size(), Ordering::SeqCst);

        let status = TxStatus::Queued;
        let monitored_tx = MonitoredTx {
            tx: tx.tx,
            txid,
            address: None,
            initial_broadcast: get_timestamp(),
            initial_height: current_height,
            last_checked: get_timestamp(),
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

    /// Replace a TX with a new RBF tx.
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

        let status = self
            .determine_tx_status(&tx_result, &monitored_tx.status)
            .await?;

        let new_tx = MonitoredTx {
            tx,
            txid: new_txid,
            address: tx_result
                .details
                .first()
                .and_then(|detail| detail.address.clone()),
            initial_broadcast: get_timestamp(),
            initial_height: current_height,
            last_checked: get_timestamp(),
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

        if new_tip != chain_state.current_tip {
            // Send new tip notification
            let _ = self.block_tx.send(new_height);

            let mut current_hash: BlockHash;
            let mut new_blocks = vec![(new_tip, new_height)];
            let mut reorg_detected = false;
            let mut reorg_depth = 0;

            for i in 1..=self.finality_depth {
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
            chain_state.current_tip = new_tip;
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
                    tx.status = self.determine_tx_status(&tx_result, &tx.status).await?;

                    if let TxStatus::InMempool { .. } = tx.status {
                        info!("Rebroadcasting tx {} {tx:?}", tx.tx.compute_txid());
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
                TxStatus::Queued | TxStatus::Confirmed { .. } | TxStatus::Replaced { .. } => {
                    let tx_result = self.client.get_transaction(txid, None).await?;
                    let new_status = self
                        .determine_tx_status(&tx_result, &monitored_tx.status)
                        .await?;

                    monitored_tx.status = new_status;
                }
                TxStatus::InMempool { height, .. } => {
                    let tx_result = self.client.get_transaction(txid, None).await?;
                    let mut new_status = self
                        .determine_tx_status(&tx_result, &monitored_tx.status)
                        .await?;

                    // If status is still InMempool, check for how many block it has been in mempool and rebroadcast every REBROADCAST_EACH_N_BLOCK
                    if let TxStatus::InMempool { .. } = new_status {
                        let current_height = self.client.get_block_count().await?;
                        if (current_height.saturating_sub(*height)) >= REBROADCAST_EACH_N_BLOCK {
                            new_status = self
                                .attempt_rebroadcast(txid, &monitored_tx.tx, &new_status)
                                .await?
                        }
                    }

                    monitored_tx.status = new_status;
                }
                _ => {}
            }

            monitored_tx.last_checked = get_timestamp();
        }

        Ok(())
    }

    async fn determine_tx_status(
        &self,
        tx_result: &GetTransactionResult,
        current_status: &TxStatus,
    ) -> Result<TxStatus> {
        let confirmations = tx_result.info.confirmations as u64;
        let status = if confirmations > 0 {
            let block_hash = tx_result
                .info
                .blockhash
                .ok_or(MonitorError::BlockHashNotSet)?;
            let block_height = self
                .client
                .get_block_info(&block_hash)
                .await
                .map(|header| header.height as u64)
                .unwrap_or(0);

            if confirmations >= self.finality_depth {
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
                    TxStatus::InMempool {
                        base_fee,
                        timestamp: get_timestamp(),
                        height: entry.height,
                    }
                }
                Err(_) => {
                    if *current_status == TxStatus::Queued {
                        return Ok(current_status.clone());
                    }

                    tracing::info!("Tx {} was evicted from mempool.", tx_result.info.txid);
                    TxStatus::Evicted {
                        last_seen: get_timestamp(),
                        rebroadcast_attempts: 0,
                        last_error: None,
                    }
                }
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

    async fn handle_evicted(&self) -> Result<()> {
        let mut txs = self.monitored_txs.write().await;

        for (txid, monitored_tx) in txs.iter_mut() {
            if let TxStatus::Evicted {
                rebroadcast_attempts,
                ..
            } = &monitored_tx.status
            {
                if *rebroadcast_attempts < self.config.max_rebroadcast_attempts {
                    let now = get_timestamp();

                    match self
                        .attempt_rebroadcast(txid, &monitored_tx.tx, &monitored_tx.status)
                        .await
                    {
                        Ok(new_status) => {
                            info!("Successfully rebroadcast tx {txid}");
                            monitored_tx.status = new_status;
                        }
                        Err(e) => {
                            info!("Failed to rebroadcast tx {txid}: {e}");
                            monitored_tx.status = TxStatus::Evicted {
                                last_seen: now,
                                rebroadcast_attempts: rebroadcast_attempts + 1,
                                last_error: Some(e.to_string()),
                            };
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn attempt_rebroadcast(
        &self,
        txid: &Txid,
        _tx: &Transaction,
        current_status: &TxStatus,
    ) -> Result<TxStatus> {
        warn!("Rebroadcasting txid: {txid} with current_status {current_status:?}");
        let raw_tx_hex = self.client.get_raw_transaction_hex(txid, None).await?;
        self.client.send_raw_transaction(raw_tx_hex).await?;
        let tx_result = self.client.get_transaction(txid, None).await?;
        self.determine_tx_status(&tx_result, current_status).await
    }

    /// Get the status of a monitored transaction by its Txid
    pub async fn get_tx_status(&self, txid: &Txid) -> Option<TxStatus> {
        self.get_monitored_tx(txid).await.map(|tx| tx.status)
    }

    /// Get a monitored transaction by its Txid
    pub async fn get_monitored_tx(&self, txid: &Txid) -> Option<MonitoredTx> {
        self.monitored_txs.read().await.get(txid).cloned()
    }

    /// Get all monitored transactions.
    pub async fn get_monitored_txs(&self) -> HashMap<Txid, MonitoredTx> {
        self.monitored_txs.read().await.clone()
    }

    /// Get the last monitored transaction.
    pub async fn get_last_tx(&self) -> Option<(Txid, MonitoredTx)> {
        let last_txid = (*self.last_tx.lock().await)?;
        let tx = self.monitored_txs.read().await.get(&last_txid)?.to_owned();
        Some((last_txid, tx))
    }

    /// Set the next_txid for a given transaction.
    pub async fn set_next_tx(&self, txid: &Txid, next_txid: Txid) {
        let mut monitored_txs = self.monitored_txs.write().await;
        if let Some(parent) = monitored_txs.get_mut(txid) {
            parent.next_txid = Some(next_txid);
        }
    }

    /// Fetch and update the status of multiple transactions.
    pub async fn update_txs_status(&self, txids: &[Txid]) -> Result<()> {
        let mut monitored_txs = self.monitored_txs.write().await;
        for txid in txids {
            if let Some(entry) = monitored_txs.get_mut(txid) {
                if let Ok(tx_result) = self.client.get_transaction(txid, None).await {
                    entry.status = self.determine_tx_status(&tx_result, &entry.status).await?;
                    entry.last_checked = get_timestamp();
                    entry.address = tx_result
                        .details
                        .first()
                        .and_then(|detail| detail.address.clone());
                }
            }
        }
        Ok(())
    }
}
