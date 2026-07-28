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
use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, error, info, instrument, trace};

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
        base_fee: f64,
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

/// Select which transactions to prune, oldest first, until the map is back under
/// both the history and size limits. The protected txid is never selected.
fn select_txs_to_prune(
    txs: &HashMap<Txid, MonitoredTx>,
    total_size: usize,
    config: &MonitoringConfig,
    protected_txid: Option<Txid>,
) -> Vec<Txid> {
    if txs.len() <= config.history_limit && total_size <= config.max_history_size {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    for (txid, tx) in txs {
        if Some(*txid) == protected_txid {
            continue;
        }

        let is_prunable = match &tx.status {
            TxStatus::Finalized { .. } | TxStatus::Replaced { .. } => true,
            TxStatus::Evicted {
                rebroadcast_attempts,
                ..
            } => *rebroadcast_attempts >= config.max_rebroadcast_attempts,
            _ => false,
        };

        if is_prunable {
            candidates.push((tx.initial_broadcast, *txid, tx.tx.total_size()));
        }
    }
    candidates.sort_unstable();

    let mut remaining_count = txs.len();
    let mut remaining_size = total_size;
    let mut to_prune = Vec::new();
    for (_, txid, tx_size) in candidates {
        if remaining_count <= config.history_limit && remaining_size <= config.max_history_size {
            break;
        }
        to_prune.push(txid);
        remaining_count -= 1;
        remaining_size = remaining_size.saturating_sub(tx_size);
    }
    to_prune
}

/// The kind of transaction being monitored.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
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
    /// BlockHash not set.
    #[error("BlockHash not set")]
    BlockHashNotSet,
    /// Previous transaction is not monitored.
    #[error("Previous transaction not monitored: {0}")]
    PrevTxNotMonitored(Txid),
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
    chain_state: Mutex<ChainState>,
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
                chain_state: Mutex::new(ChainState::default()),
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

        let mut chain_state = self.chain_state.lock().await;
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
                .transaction()?;

            let reveal_wtxid = reveal_tx.compute_wtxid();
            let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

            // Assumes that no wallet can hold both txs utxos
            if reveal_hash.starts_with(REVEAL_TX_PREFIX)
                && parse_relevant_transaction(&reveal_tx).is_ok()
            {
                let commit_txid = reveal_tx.input[0].previous_output.txid;
                let Some(commit_tx) = self
                    .client
                    .get_transaction(&commit_txid, None)
                    .await
                    .ok()
                    .and_then(|result| result.transaction().ok())
                else {
                    continue;
                };

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
        self.check_transactions().await;
        Ok(())
    }

    /// Run monitoring to keep track of TX status and chain re-orgs
    pub async fn run(self: Arc<Self>, mut shutdown_signal: GracefulShutdown) {
        let mut check_interval = interval(Duration::from_secs(self.config.check_interval));
        check_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut rebroadcast_interval = interval(Duration::from_secs(self.config.rebroadcast_delay));
        rebroadcast_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = &mut shutdown_signal => {
                    info!("Shutting down monitoring service");
                    return;
                }
                _ = check_interval.tick() => {
                    if let Err(e) = self.check_chain_state().await {
                        error!("Error checking chain state: {e}");
                    }
                    self.check_transactions().await;
                    self.prune_old_transactions().await;
                }
                _ = rebroadcast_interval.tick() => {
                    self.handle_evicted().await;
                    self.rebroadcast_last_txs().await;
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

        let current_height = self.client.get_block_count().await?;

        let mut monitored_txs = self.monitored_txs.write().await;
        if monitored_txs.contains_key(&txid) {
            return Err(MonitorError::AlreadyMonitored);
        }

        if let Some(prev_tx_id) = prev_txid {
            let Some(prev_tx) = monitored_txs.get_mut(&prev_tx_id) else {
                return Err(MonitorError::PrevTxNotMonitored(prev_tx_id));
            };
            prev_tx.next_txid = Some(txid);
        }

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

        monitored_txs.insert(txid, monitored_tx);
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

        let (old_tip, recent_blocks) = {
            let chain_state = self.chain_state.lock().await;
            (chain_state.current_tip, chain_state.recent_blocks.clone())
        };

        if new_tip == old_tip {
            return Ok(());
        }

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

            if let Some(pos) = recent_blocks
                .iter()
                .position(|&(hash, _)| hash == current_hash)
            {
                if pos + 1 != i as usize {
                    reorg_detected = true;
                    reorg_depth = i;
                }
                break;
            }
        }

        if reorg_detected {
            // Handle transaction status updates due to reorg
            self.handle_reorg(reorg_depth).await;
        }

        let mut chain_state = self.chain_state.lock().await;
        if chain_state.current_tip == old_tip {
            chain_state.current_height = new_height;
            chain_state.current_tip = new_tip;
            chain_state.recent_blocks = new_blocks;
        }

        Ok(())
    }

    async fn handle_reorg(&self, depth: u64) {
        let affected_txs: Vec<(Txid, TxStatus)> = self
            .monitored_txs
            .read()
            .await
            .iter()
            .filter_map(|(txid, tx)| match tx.status {
                TxStatus::Confirmed { confirmations, .. } if confirmations <= depth => {
                    Some((*txid, tx.status.clone()))
                }
                _ => None,
            })
            .collect();

        for (txid, old_status) in affected_txs {
            let new_status = match self.fetch_tx_status(&txid, &old_status).await {
                Ok(status) => status,
                Err(e) => {
                    error!("Failed to check tx {txid} after reorg: {e}");
                    continue;
                }
            };

            if let TxStatus::InMempool { .. } = new_status {
                info!("Rebroadcasting tx {txid} after reorg of depth {depth}");
                if let Err(e) = self.attempt_rebroadcast(&txid, &new_status).await {
                    error!("Failed to rebroadcast tx {txid} after reorg: {e}");
                }
            }

            self.apply_tx_status(&txid, &old_status, new_status).await;
        }
    }

    async fn apply_tx_status(&self, txid: &Txid, expected_status: &TxStatus, new_status: TxStatus) {
        let mut txs = self.monitored_txs.write().await;
        if let Some(tx) = txs.get_mut(txid) {
            if tx.status == *expected_status {
                tx.status = new_status;
            }
        }
    }

    #[instrument(skip(self))]
    async fn check_transactions(&self) {
        let txs: Vec<(Txid, TxStatus)> = self
            .monitored_txs
            .read()
            .await
            .iter()
            .map(|(txid, tx)| (*txid, tx.status.clone()))
            .collect();

        for (txid, old_status) in txs {
            let new_status = match self.check_tx(&txid, &old_status).await {
                Ok(new_status) => new_status,
                Err(e) => {
                    error!("Failed to check monitored tx {txid}: {e}");
                    None
                }
            };

            let mut monitored_txs = self.monitored_txs.write().await;
            if let Some(monitored_tx) = monitored_txs.get_mut(&txid) {
                if let Some(new_status) = new_status {
                    if monitored_tx.status == old_status {
                        monitored_tx.status = new_status;
                    }
                }
                monitored_tx.last_checked = get_timestamp();
            }
        }
    }

    /// Check a single transaction against the chain and compute its new status.
    /// Returns `None` when the status does not need to be re-evaluated.
    async fn check_tx(&self, txid: &Txid, old_status: &TxStatus) -> Result<Option<TxStatus>> {
        match old_status {
            // Check non-finalized TXs
            TxStatus::Queued | TxStatus::Confirmed { .. } | TxStatus::Replaced { .. } => {
                match self.client.get_transaction(txid, None).await {
                    Ok(tx_result) => Ok(Some(
                        self.determine_tx_status(&tx_result, old_status).await?,
                    )),
                    Err(_) => Ok(None),
                }
            }
            // Check evicted TXs that have already been rebroadcasted at least once
            TxStatus::Evicted {
                rebroadcast_attempts,
                ..
            } if *rebroadcast_attempts > 0 => {
                Ok(Some(self.fetch_tx_status(txid, old_status).await?))
            }
            TxStatus::InMempool { height, .. } => {
                let new_status = self.fetch_tx_status(txid, old_status).await?;

                // If status is still InMempool, check for how many block it has been in mempool and rebroadcast every REBROADCAST_EACH_N_BLOCK
                if let TxStatus::InMempool { .. } = new_status {
                    let current_height = self.client.get_block_count().await?;
                    if (current_height.saturating_sub(*height)) >= REBROADCAST_EACH_N_BLOCK {
                        if let Err(e) = self.attempt_rebroadcast(txid, &new_status).await {
                            debug!("Failed to rebroadcast in-mempool tx {txid}: {e}");
                        }
                    }
                }

                Ok(Some(new_status))
            }
            _ => Ok(None),
        }
    }

    /// Fetch a transaction from the wallet and determine its new status.
    async fn fetch_tx_status(&self, txid: &Txid, current_status: &TxStatus) -> Result<TxStatus> {
        let tx_result = self.client.get_transaction(txid, None).await?;
        self.determine_tx_status(&tx_result, current_status).await
    }

    async fn determine_tx_status(
        &self,
        tx_result: &GetTransactionResult,
        current_status: &TxStatus,
    ) -> Result<TxStatus> {
        let confirmations = tx_result.info.confirmations;
        let status = if confirmations > 0 {
            let block_hash = tx_result
                .info
                .blockhash
                .ok_or(MonitorError::BlockHashNotSet)?;
            let block_height = match tx_result.info.blockheight {
                Some(height) => u64::from(height),
                None => self.client.get_block_info(&block_hash).await?.height as u64,
            };
            let confirmations = confirmations as u64;

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
        } else if confirmations < 0 {
            if let Some(by_txid) = tx_result.info.wallet_conflicts.first().copied() {
                TxStatus::Replaced { by_txid }
            } else {
                TxStatus::Evicted {
                    last_seen: get_timestamp(),
                    rebroadcast_attempts: 0,
                    last_error: None,
                }
            }
        } else {
            match self.client.get_mempool_entry(&tx_result.info.txid).await {
                Ok(entry) => TxStatus::InMempool {
                    base_fee: entry.fees.base.to_sat() as f64,
                    timestamp: get_timestamp(),
                    height: entry.height,
                },
                Err(_) => match current_status {
                    TxStatus::Queued | TxStatus::Evicted { .. } | TxStatus::Replaced { .. } => {
                        current_status.clone()
                    }
                    _ => TxStatus::Evicted {
                        last_seen: get_timestamp(),
                        rebroadcast_attempts: 0,
                        last_error: None,
                    },
                },
            }
        };

        let was_pending = !matches!(
            current_status,
            TxStatus::Queued | TxStatus::Evicted { .. } | TxStatus::Replaced { .. }
        );
        match &status {
            TxStatus::Evicted { .. } if was_pending => {
                info!("Tx {} was evicted from mempool.", tx_result.info.txid);
            }
            TxStatus::Replaced { by_txid } if was_pending => {
                info!(
                    "Tx {} was replaced by conflicting tx {by_txid}.",
                    tx_result.info.txid
                );
            }
            _ => {}
        }

        Ok(status)
    }

    async fn prune_old_transactions(&self) {
        let protected_txid = *self.last_tx.lock().await;
        let mut txs = self.monitored_txs.write().await;
        let to_prune = select_txs_to_prune(
            &txs,
            self.total_size.load(Ordering::SeqCst),
            &self.config,
            protected_txid,
        );

        for txid in to_prune {
            if let Some(removed_tx) = txs.remove(&txid) {
                let tx_size = removed_tx.tx.total_size();
                self.total_size.fetch_sub(tx_size, Ordering::SeqCst);
            }
        }
    }

    async fn handle_evicted(&self) {
        let evicted_txs: Vec<(Txid, u32, TxStatus)> = self
            .monitored_txs
            .read()
            .await
            .iter()
            .filter_map(|(txid, tx)| match &tx.status {
                TxStatus::Evicted {
                    rebroadcast_attempts,
                    ..
                } if *rebroadcast_attempts < self.config.max_rebroadcast_attempts => {
                    Some((*txid, *rebroadcast_attempts, tx.status.clone()))
                }
                _ => None,
            })
            .collect();

        for (txid, rebroadcast_attempts, old_status) in evicted_txs {
            let result = self.attempt_rebroadcast(&txid, &old_status).await;
            let now = get_timestamp();

            let new_status = match result {
                Ok(_) => {
                    info!("Attempted to rebroadcast tx {txid}");
                    TxStatus::Evicted {
                        last_seen: now,
                        rebroadcast_attempts: rebroadcast_attempts + 1,
                        last_error: None,
                    }
                }
                Err(e) => {
                    info!("Failed to rebroadcast tx {txid}: {e}");
                    TxStatus::Evicted {
                        last_seen: now,
                        rebroadcast_attempts: rebroadcast_attempts + 1,
                        last_error: Some(e.to_string()),
                    }
                }
            };

            self.apply_tx_status(&txid, &old_status, new_status).await;
        }
    }

    async fn rebroadcast_last_txs(&self) {
        const TXS_NUMBER_TO_REBROADCAST: usize = 100;
        trace!("Rebroadcasting last {TXS_NUMBER_TO_REBROADCAST} txs");

        let last_txid = *self.last_tx.lock().await;

        let to_rebroadcast: Vec<(Txid, TxStatus)> = {
            let monitored_txs = self.monitored_txs.read().await;
            let mut chain = Vec::new();
            let mut current_txid = last_txid;
            while let Some(txid) = current_txid {
                if chain.len() >= TXS_NUMBER_TO_REBROADCAST {
                    break;
                }
                // A missing tx means the rest of the chain was pruned
                let Some(tx) = monitored_txs.get(&txid) else {
                    debug!("End of rebroadcast chain: tx {txid} is not monitored anymore");
                    break;
                };
                // Break on first finalized TX
                if let TxStatus::Finalized { .. } = tx.status {
                    break;
                }
                chain.push((txid, tx.status.clone()));
                current_txid = tx.prev_txid;
            }
            chain
        };

        for (txid, status) in to_rebroadcast {
            let _ = self.attempt_rebroadcast(&txid, &status).await;
        }
    }

    async fn attempt_rebroadcast(&self, txid: &Txid, current_status: &TxStatus) -> Result<()> {
        debug!("Rebroadcasting txid: {txid} with current_status {current_status:?}");
        if let Ok(result) = self.client.get_transaction(txid, None).await {
            self.client.send_raw_transaction(&result.hex).await?;
        } else if let Ok(result) = self.client.get_raw_transaction_hex(txid, None).await {
            self.client.send_raw_transaction(result).await?;
        } else {
            return Err(anyhow!("Failed to retrieve hex and rebroadcast {txid}").into());
        }

        Ok(())
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

    /// Get monitored transactions currently in the mempool.
    pub async fn get_in_mempool_txs(&self) -> Vec<(Txid, MonitoredTx)> {
        self.monitored_txs
            .read()
            .await
            .iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::InMempool { .. }))
            .map(|(txid, tx)| (*txid, tx.clone()))
            .collect()
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
        for txid in txids {
            let Some(old_status) = self.get_tx_status(txid).await else {
                continue;
            };

            let Ok(tx_result) = self.client.get_transaction(txid, None).await else {
                continue;
            };
            let new_status = match self.determine_tx_status(&tx_result, &old_status).await {
                Ok(status) => status,
                Err(e) => {
                    error!("Failed to determine status of tx {txid}: {e}");
                    continue;
                }
            };
            let address = tx_result
                .details
                .first()
                .and_then(|detail| detail.address.clone());

            let mut monitored_txs = self.monitored_txs.write().await;
            if let Some(entry) = monitored_txs.get_mut(txid) {
                if entry.status == old_status {
                    entry.status = new_status;
                }
                entry.last_checked = get_timestamp();
                entry.address = address;
            }
        }
        Ok(())
    }

    /// Get all monitored in mempool commit transactions txids
    pub async fn get_in_mempool_commit_transaction_ids(&self) -> Vec<Txid> {
        self.monitored_txs
            .read()
            .await
            .iter()
            .filter_map(|monitored_tx| {
                if matches!(monitored_tx.1.status, TxStatus::InMempool { .. })
                    && monitored_tx.1.kind == MonitoredTxKind::Commit
                {
                    Some(*monitored_tx.0)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINALITY_DEPTH: u64 = 8;

    fn dummy_txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    fn monitored_tx(status: TxStatus, initial_broadcast: u64) -> MonitoredTx {
        MonitoredTx {
            tx: dummy_tx(),
            txid: dummy_txid(0),
            address: None,
            initial_broadcast,
            initial_height: 0,
            last_checked: 0,
            status,
            prev_txid: None,
            next_txid: None,
            kind: MonitoredTxKind::Commit,
        }
    }

    fn in_mempool_status() -> TxStatus {
        TxStatus::InMempool {
            base_fee: 100.0,
            timestamp: 0,
            height: 1,
        }
    }

    fn confirmed_status() -> TxStatus {
        TxStatus::Confirmed {
            block_hash: BlockHash::all_zeros(),
            block_height: 1,
            confirmations: 1,
        }
    }

    fn finalized_status() -> TxStatus {
        TxStatus::Finalized {
            block_hash: BlockHash::all_zeros(),
            block_height: 1,
            confirmations: FINALITY_DEPTH,
        }
    }

    fn evicted_status(rebroadcast_attempts: u32) -> TxStatus {
        TxStatus::Evicted {
            last_seen: 0,
            rebroadcast_attempts,
            last_error: None,
        }
    }

    fn prune_config(history_limit: usize, max_history_size: usize) -> MonitoringConfig {
        MonitoringConfig {
            history_limit,
            max_history_size,
            ..Default::default()
        }
    }

    #[test]
    fn prune_nothing_when_under_limits() {
        let txs = HashMap::from([(dummy_txid(1), monitored_tx(finalized_status(), 1))]);
        let to_prune = select_txs_to_prune(&txs, 10, &prune_config(10, 1_000), None);
        assert!(to_prune.is_empty());
    }

    #[test]
    fn prune_oldest_finalized_first_down_to_history_limit() {
        let txs = HashMap::from([
            (dummy_txid(1), monitored_tx(finalized_status(), 30)),
            (dummy_txid(2), monitored_tx(finalized_status(), 10)),
            (dummy_txid(3), monitored_tx(finalized_status(), 20)),
            (dummy_txid(4), monitored_tx(in_mempool_status(), 40)),
        ]);
        let to_prune = select_txs_to_prune(&txs, 0, &prune_config(2, 1_000), None);
        assert_eq!(to_prune, vec![dummy_txid(2), dummy_txid(3)]);
    }

    #[test]
    fn prune_down_to_size_limit() {
        let tx_size = dummy_tx().total_size();
        let txs = HashMap::from([
            (dummy_txid(1), monitored_tx(finalized_status(), 1)),
            (dummy_txid(2), monitored_tx(finalized_status(), 2)),
            (dummy_txid(3), monitored_tx(finalized_status(), 3)),
            (dummy_txid(4), monitored_tx(finalized_status(), 4)),
        ]);
        // Over size budget by two transactions
        let to_prune = select_txs_to_prune(&txs, 4 * tx_size, &prune_config(10, 2 * tx_size), None);
        assert_eq!(to_prune, vec![dummy_txid(1), dummy_txid(2)]);
    }

    #[test]
    fn prune_finalized_and_replaced_oldest_first() {
        let txs = HashMap::from([
            (
                dummy_txid(1),
                monitored_tx(
                    TxStatus::Replaced {
                        by_txid: dummy_txid(9),
                    },
                    1,
                ),
            ),
            (
                dummy_txid(2),
                monitored_tx(
                    TxStatus::Replaced {
                        by_txid: dummy_txid(10),
                    },
                    2,
                ),
            ),
            (dummy_txid(3), monitored_tx(finalized_status(), 100)),
        ]);
        let to_prune = select_txs_to_prune(&txs, 0, &prune_config(1, 1_000), None);
        assert_eq!(to_prune, vec![dummy_txid(1), dummy_txid(2)]);
    }

    #[test]
    fn prune_never_selects_active_txs() {
        let txs = HashMap::from([
            (dummy_txid(1), monitored_tx(TxStatus::Queued, 1)),
            (dummy_txid(2), monitored_tx(in_mempool_status(), 2)),
            (dummy_txid(3), monitored_tx(confirmed_status(), 3)),
            // Evicted txs below the retry limit are still expected to be rebroadcast and recover.
            (dummy_txid(4), monitored_tx(evicted_status(1), 4)),
        ]);
        let to_prune = select_txs_to_prune(&txs, 0, &prune_config(1, 1_000), None);
        assert!(to_prune.is_empty());
    }

    #[test]
    fn prune_selects_terminally_evicted_txs() {
        let txs = HashMap::from([
            (
                dummy_txid(1),
                monitored_tx(
                    evicted_status(MonitoringConfig::default().max_rebroadcast_attempts),
                    1,
                ),
            ),
            (dummy_txid(2), monitored_tx(in_mempool_status(), 2)),
        ]);
        let to_prune = select_txs_to_prune(&txs, 0, &prune_config(1, 1_000), None);
        assert_eq!(to_prune, vec![dummy_txid(1)]);
    }

    #[test]
    fn prune_never_selects_protected_last_tx() {
        let txs = HashMap::from([
            (dummy_txid(1), monitored_tx(finalized_status(), 1)),
            (dummy_txid(2), monitored_tx(finalized_status(), 2)),
        ]);
        let to_prune = select_txs_to_prune(&txs, 0, &prune_config(1, 1_000), Some(dummy_txid(1)));
        assert_eq!(to_prune, vec![dummy_txid(2)]);
    }
}
