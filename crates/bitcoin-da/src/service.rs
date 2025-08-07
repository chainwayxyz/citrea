//! This module provides the Bitcoin DA service implementation.

// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use bitcoin::block::Header;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, CompactTarget, Transaction, Txid, Wtxid};
use bitcoincore_rpc::{Client, Error as BitcoinError, Error, RpcApi, RpcError};
use borsh::BorshDeserialize;
use citrea_common::utils::read_env;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::MAX_TX_BODY_SIZE;
use lru::LruCache;
use reth_tasks::shutdown::GracefulShutdown;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaSpec, DaTxRequest, DataOnDa, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use sov_rollup_interface::zk::Proof;
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::error::{BitcoinServiceError, MempoolRejection};
use crate::fee::{BumpFeeMethod, FeeService};
use crate::helpers::backup::backup_txs_to_file;
use crate::helpers::builders::body_builders::{create_inscription_transactions, DaTxs, RawTxData};
use crate::helpers::builders::TxWithId;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use crate::helpers::{merkle_tree, TransactionKind};
use crate::metrics::BITCOIN_DA_METRICS as BM;
use crate::monitoring::{MonitoredTxKind, MonitoringConfig, MonitoringService, TxStatus};
use crate::network_constants::NetworkConstants;
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::short_proof::BitcoinHeaderShortProof;
use crate::spec::transaction::TransactionWrapper;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::tx_signer::{SignedTxPair, TxSigner};
use crate::verifier::{
    BitcoinVerifier, MINIMUM_WITNESS_COMMITMENT_SIZE, WITNESS_COMMITMENT_PREFIX,
};
use crate::REVEAL_OUTPUT_AMOUNT;

pub(crate) type Result<T> = std::result::Result<T, BitcoinServiceError>;

const POLLING_INTERVAL: u64 = 10; // seconds

/// Map sov Network to Bitcoin Network.
pub fn network_to_bitcoin_network(network: &Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet4,
        Network::Devnet => bitcoin::Network::Signet,
        Network::Nightly | Network::TestNetworkWithForks => bitcoin::Network::Regtest,
    }
}

/// Runtime configuration for the DA service.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BitcoinServiceConfig {
    /// The URL of the Bitcoin node to connect to.
    pub node_url: String,
    /// Username to authenticate with the Bitcoin node.
    pub node_username: String,
    /// Password to authenticate with the Bitcoin node.
    pub node_password: String,

    /// DA private key of the sequencer.
    pub da_private_key: Option<String>,

    /// Absolute path to the directory where the txs will be written to.
    pub tx_backup_dir: String,

    /// Monitoring configuration.
    pub monitoring: Option<MonitoringConfig>,
    /// The URL of the mempool.space API.
    pub mempool_space_url: Option<String>,
}

impl citrea_common::FromEnv for BitcoinServiceConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            node_url: read_env("NODE_URL")?,
            node_username: read_env("NODE_USERNAME")?,
            node_password: read_env("NODE_PASSWORD")?,
            da_private_key: read_env("DA_PRIVATE_KEY").ok(),
            tx_backup_dir: read_env("TX_BACKUP_DIR")?,
            monitoring: MonitoringConfig::from_env().ok(),
            mempool_space_url: read_env("MEMPOOL_SPACE_URL").ok(),
        })
    }
}

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug)]
pub struct BitcoinService {
    client: Arc<Client>,
    pub(crate) network: bitcoin::Network,
    network_constants: NetworkConstants,
    pub(crate) da_private_key: Option<SecretKey>,
    pub(crate) reveal_tx_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
    pub(crate) tx_backup_dir: PathBuf,
    /// Monitoring service for tracking transaction status.
    pub monitoring: Arc<MonitoringService>,
    fee: FeeService,
    l1_block_hash_to_height: Arc<Mutex<LruCache<BlockHash, usize>>>,
    tx_queue: Arc<Mutex<VecDeque<SignedTxPair>>>,
    pub(crate) tx_signer: TxSigner,
}

impl BitcoinService {
    #[allow(clippy::too_many_arguments)]
    fn new(
        client: Arc<Client>,
        network: bitcoin::Network,
        network_constants: NetworkConstants,
        monitoring: Arc<MonitoringService>,
        fee: FeeService,
        inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
        da_private_key: Option<SecretKey>,
        reveal_tx_prefix: Vec<u8>,
        tx_backup_dir: PathBuf,
    ) -> Self {
        Self {
            tx_signer: TxSigner::new(client.clone()),
            client,
            network_constants,
            network,
            da_private_key,
            reveal_tx_prefix,
            inscribes_queue,
            tx_backup_dir,
            monitoring,
            fee,
            l1_block_hash_to_height: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(100).unwrap(),
            ))),
            tx_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Create a new instance of the DA service from the given configuration.
    #[allow(clippy::too_many_arguments)]
    pub async fn from_config(
        config: &BitcoinServiceConfig,
        chain_params: RollupParams,
        client: Arc<Client>,
        network: bitcoin::Network,
        network_constants: NetworkConstants,
        monitoring: Arc<MonitoringService>,
        fee_service: FeeService,
        require_wallet_check: bool,
        inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
    ) -> Result<Self> {
        if require_wallet_check
            && client
                .list_wallets()
                .await
                .expect("Failed to list loaded wallets")
                .is_empty()
        {
            tracing::warn!("No loaded wallet found!");
        }

        let tx_backup_dir = std::path::Path::new(&config.tx_backup_dir);
        if !tx_backup_dir.exists() {
            std::fs::create_dir_all(tx_backup_dir)
                .context("Failed to create tx backup directory")?;
        }

        let da_private_key = config
            .da_private_key
            .as_ref()
            .map(|pk| SecretKey::from_str(pk))
            .transpose()
            .context("Invalid private key")?;

        Ok(Self::new(
            client,
            network,
            network_constants,
            monitoring,
            fee_service,
            inscribes_queue,
            da_private_key,
            chain_params.reveal_tx_prefix,
            tx_backup_dir.to_path_buf(),
        ))
    }

    /// Run the task to process the DA commands from the queue.
    #[instrument(name = "BitcoinDA", skip_all)]
    pub async fn run_da_queue(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<TxRequestWithNotifier<TxidWrapper>>,
        mut new_block_rx: UnboundedReceiver<u64>,
        mut shutdown: GracefulShutdown,
    ) {
        trace!("BitcoinDA queue is initialized. Waiting for the first request...");
        let mut fee_rate_multiplier = self.fee.base_fee_rate_multiplier();

        loop {
            select! {
                biased;
                _ = &mut shutdown => {
                    debug!("DA queue service received shutdown signal");
                    break;
                }
                new_height_opt = new_block_rx.recv() => {
                    if let Some(new_height) = new_height_opt {
                        trace!("New da block height {new_height}. Processing transaction queue.");
                        if let Err(e) = self.process_transaction_queue().await {
                            error!(?e, "Error processing queue on new block");
                        }
                    }
                }
                request_opt = rx.recv() => {
                    if let Some(request) = request_opt {
                        trace!("A new request is received");

                        loop {
                            // Build and queue tx with retries:
                            let fee_sat_per_vbyte = match self.fee.get_fee_rate().await {
                                Ok(rate) => (rate as f64 * fee_rate_multiplier).ceil() as u64,
                                Err(e) => {
                                    error!(?e, "Failed to call get_fee_rate. Retrying...");
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                    continue;
                                }
                            };
                            match self
                                .send_transaction_with_fee_rate(
                                    request.tx_request.clone(),
                                    fee_sat_per_vbyte,
                                )
                                .await
                            {
                                Ok(txs) => {
                                    let txid = txs.last().unwrap()[1].id;
                                    let tx_id = TxidWrapper(txid);
                                    info!(%txid, "Sent tx to BitcoinDA");
                                    let _ = request.notify.send(Ok(tx_id));

                                    fee_rate_multiplier = self.fee.base_fee_rate_multiplier();
                                }
                                Err(e) => {
                                    error!(?e, "Failed to send transaction to DA layer");
                                    tokio::time::sleep(Duration::from_secs(1)).await;

                                    if let BitcoinServiceError::MempoolRejection(MempoolRejection::MinRelayFeeNotMet) = e {
                                        fee_rate_multiplier = self.fee.get_next_fee_rate_multiplier(fee_rate_multiplier);
                                    }

                                    if let BitcoinServiceError::QueueNotEmpty = e {
                                        let _ = self.process_transaction_queue().await;
                                    }

                                    continue;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Queue and try sending transaction to DA
    pub async fn send_transaction_with_fee_rate(
        &self,
        tx_request: DaTxRequest,
        fee_sat_per_vbyte: u64,
    ) -> Result<Vec<[TxWithId; 2]>> {
        let now = Instant::now();
        // Prevent sending tx to DA while transaction queue is not empty
        // otherwise, the tx that will be built may use the same UTXO as the one in the queue
        if !self.tx_queue.lock().await.is_empty() {
            return Err(BitcoinServiceError::QueueNotEmpty);
        }

        let da_txs = self
            .create_da_transactions_with_fee_rate(tx_request, fee_sat_per_vbyte)
            .await?;
        let signed_txs = self.tx_signer.sign_da_txs(da_txs).await?;
        self.test_mempool_accept_queue_tx(&signed_txs).await?;

        // backup to file after mempool acceptance
        backup_txs_to_file(&self.tx_backup_dir, &signed_txs)?;

        let txs = signed_txs
            .iter()
            .map(|tx| tx.clone().into_txs_with_id())
            .collect::<Vec<_>>();
        self.monitoring
            .monitor_transaction_chain(txs.clone())
            .await?;

        // Queue transactions
        self.queue_transactions(signed_txs).await;

        // Process transaction queue.
        self.process_transaction_queue().await?;

        BM.transaction_queue_processing_time
            .record(Instant::now().saturating_duration_since(now).as_secs_f64());

        Ok(txs)
    }

    /// Retrieves the most recent spendable UTXO from the transaction chain on startup.
    #[instrument(level = "trace", skip_all, ret)]
    pub(crate) async fn get_prev_utxo(&self) -> Option<UTXO> {
        let (txid, tx) = self.monitoring.get_last_tx().await?;

        let utxos = tx.to_utxos()?;

        // Check that tx out is still spendable
        // If not found, utxo is already spent
        self.client.get_tx_out(&txid, 0, Some(true)).await.ok()??;

        // Return first vout
        utxos.into_iter().next()
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub(crate) async fn get_utxos(&self) -> Result<Vec<UTXO>> {
        let utxos = self
            .client
            .list_unspent(Some(0), None, None, None, None)
            .await?;
        if utxos.is_empty() {
            return Err(BitcoinServiceError::MissingUTXO);
        }

        let utxos: Vec<UTXO> = utxos
            .into_iter()
            .filter(|utxo| {
                utxo.spendable
                    && utxo.solvable
                    && utxo.amount > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
            })
            .map(Into::into)
            .collect();
        if utxos.is_empty() {
            return Err(BitcoinServiceError::MissingSpendableUTXO);
        }

        Ok(utxos)
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_pending_transactions(&self) -> Vec<Transaction> {
        self.monitoring
            .get_monitored_txs()
            .await
            .into_iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::InMempool { .. }))
            .map(|(_, monitored_tx)| monitored_tx.tx)
            .collect()
    }

    /// Sends a transaction to the Bitcoin network with a specified fee rate.
    #[instrument(level = "trace", fields(prev_utxo), ret, err, skip(self))]
    async fn create_da_transactions_with_fee_rate(
        &self,
        tx_request: DaTxRequest,
        fee_sat_per_vbyte: u64,
    ) -> Result<DaTxs> {
        let data = match tx_request {
            DaTxRequest::ZKProof(zkproof) => split_proof(zkproof)?,
            DaTxRequest::SequencerCommitment(comm) => {
                let data = DataOnDa::SequencerCommitment(comm);
                let blob = borsh::to_vec(&data).expect("DataOnDa serialize must not fail");
                RawTxData::SequencerCommitment(blob)
            }
            DaTxRequest::BatchProofMethodId(method_id) => {
                let data = DataOnDa::BatchProofMethodId(method_id);
                let blob = borsh::to_vec(&data).expect("DataOnDa serialize must not fail");
                RawTxData::BatchProofMethodId(blob)
            }
        };

        let network = self.network;

        let da_private_key = self.da_private_key.expect("No private key set");

        // get all available utxos
        let utxos = self.get_utxos().await?;
        let prev_utxo = self.get_prev_utxo().await;

        // get address from a utxo
        let address = utxos[0]
            .address
            .clone()
            .context("Missing address")?
            .require_network(network)?;

        let prefix = self.reveal_tx_prefix.clone();
        Ok(tokio::task::spawn_blocking(move || {
            // Since this is CPU bound work, we use spawn_blocking
            // to release the tokio runtime execution
            create_inscription_transactions(
                data,
                da_private_key,
                prev_utxo,
                utxos,
                address,
                fee_sat_per_vbyte,
                fee_sat_per_vbyte,
                network,
                prefix,
            )
        })
        .await??)
    }

    async fn queue_transactions(&self, txs: Vec<SignedTxPair>) {
        let txs_len = txs.len();
        self.tx_queue.lock().await.extend(txs);
        BM.transaction_queue_size.increment(txs_len as f64);
    }

    /// Send transaction out of the queue to DA until the first error.
    /// Returns the successfully sent txs.
    pub(crate) async fn process_transaction_queue(&self) -> Result<Vec<Txid>> {
        let mut queue = self.tx_queue.lock().await;

        let mut txids = Vec::new();
        while let Some(tx) = queue.front() {
            info!(
                "Processing transaction from queue. Commit: {} Reveal: {}",
                tx.commit_txid(),
                tx.reveal_txid()
            );
            if let Err(e) = self.test_mempool_accept(&tx.as_raw_txs()).await {
                warn!(?e, "Rejected by mempool");
                break;
            }

            match self.send_signed_transaction(tx).await {
                Ok(ids) => {
                    queue.pop_front();
                    BM.transaction_queue_size.decrement(1);
                    txids.extend(ids)
                }
                Err(e) => {
                    error!(?e, "Error sending signed transaction");
                    // Break on first error and return successfully sent txids
                    break;
                }
            }
        }

        // Update monitored tx status
        if let Err(e) = self.monitoring.update_txs_status(&txids).await {
            error!(?e, "Failed to update queued tx status");
        }

        Ok(txids)
    }

    pub(crate) async fn send_signed_transaction(&self, tx: &SignedTxPair) -> Result<Vec<Txid>> {
        let raw_txs = tx.as_raw_txs();
        let raw_txs_size_sum = raw_txs.iter().map(|tx| tx.len()).sum::<usize>() as f64;
        let txids = self.send_raw_transactions(&raw_txs).await?;

        match &tx.kind {
            TransactionKind::Complete
            | TransactionKind::BatchProofMethodId
            | TransactionKind::SequencerCommitment => {
                info!("Blob inscribe tx sent. Hash: {}", tx.reveal_txid())
            }
            TransactionKind::Chunks => {
                BM.transaction_size.set(raw_txs_size_sum);
                info!("Blob chunk inscribe tx sent. Hash: {}", tx.reveal_txid())
            }
            TransactionKind::Aggregate => {
                BM.transaction_size.set(raw_txs_size_sum);
                info!("Blob chunk aggregate tx sent. Hash: {}", tx.reveal_txid())
            }
            TransactionKind::Unknown(_) => unimplemented!(),
        }

        Ok(txids)
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn test_mempool_accept(&self, raw_txs: &[&Vec<u8>]) -> Result<()> {
        let results = self.client.test_mempool_accept(raw_txs).await?;

        for result in results {
            if !result.allowed.unwrap_or(false) {
                let reason = result
                    .reject_reason
                    .or(result.package_error)
                    .unwrap_or_else(|| "[testmempoolaccept] Unknown rejection".to_string());

                return Err(MempoolRejection::from_reason(reason).into());
            }
        }
        Ok(())
    }

    /// Test whether signed transactions should be accepted to the queue.
    /// Any error recoverable by mempool state changes should be queued, such as package too large or package too many transactions.
    /// When the mempool state changes, on every new block, the package limitations change accordingly.
    /// The queued transactions will be retried on every block until the transaction is accepted to mempool.
    async fn test_mempool_accept_queue_tx(&self, txs: &[SignedTxPair]) -> Result<()> {
        let raw_txs: Vec<&Vec<u8>> = txs.iter().flat_map(|v| v.as_raw_txs()).collect();

        match self.test_mempool_accept(&raw_txs).await {
            Ok(()) => Ok(()),
            Err(BitcoinServiceError::MempoolRejection(e)) if e.should_be_queued() => Ok(()),
            e => e,
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn send_raw_transactions(&self, raw_txs: &[&Vec<u8>]) -> Result<Vec<Txid>> {
        let mut txids = Vec::with_capacity(raw_txs.len());

        for tx in raw_txs {
            let txid = self.client.send_raw_transaction(tx.as_slice()).await?;
            txids.push(txid);
        }
        Ok(txids)
    }

    /// Bumps the transaction fee using the specified bump method.
    pub async fn bump_fee(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
        method: BumpFeeMethod,
    ) -> Result<Txid> {
        // Look for input tx or resolve to monitored last_tx
        let (txid, tx) = match txid {
            None => self
                .monitoring
                .get_last_tx()
                .await
                .context("No monitored tx")?,
            Some(txid) => {
                let monitored_tx = self
                    .monitoring
                    .get_monitored_tx(&txid)
                    .await
                    .context("Parent tx not found")?;
                (txid, monitored_tx)
            }
        };

        let TxStatus::InMempool { .. } = tx.status else {
            return Err(BitcoinServiceError::WrongStatusForBumping(tx.status));
        };

        let Some(utxo) = self.get_prev_utxo().await else {
            return Err(BitcoinServiceError::MissingPreviousUTXO);
        };

        let funded_psbt = match method {
            BumpFeeMethod::Cpfp => {
                self.fee
                    .bump_fee_cpfp(&tx, &txid, fee_rate, force, utxo)
                    .await
            }
            BumpFeeMethod::Rbf => self.fee.bump_fee_rbf(tx.kind, &txid).await,
        }?;

        let wallet_psbt = self
            .client
            .wallet_process_psbt(&funded_psbt, Some(true), None, None)
            .await?;

        let processed = self.client.finalize_psbt(&wallet_psbt.psbt, None).await?;

        let Some(Ok(new_tx)) = processed.transaction() else {
            return Err(BitcoinServiceError::PsbtFinalizationFailure);
        };
        let Some(raw_hex) = processed.hex else {
            return Err(BitcoinServiceError::PsbtFinalizationFailure);
        };

        self.client.test_mempool_accept(&[&raw_hex]).await?;

        let new_txid = self.client.send_raw_transaction(&raw_hex).await?;
        BM.transaction_size.set(raw_hex.len() as f64);

        match method {
            BumpFeeMethod::Cpfp => {
                self.monitoring
                    .monitor_transaction(
                        TxWithId {
                            id: new_txid,
                            tx: new_tx,
                        },
                        Some(txid),
                        None,
                        MonitoredTxKind::Cpfp,
                    )
                    .await?;
                self.monitoring.set_next_tx(&txid, new_txid).await;
                self.monitoring.update_txs_status(&[new_txid]).await?;
            }
            BumpFeeMethod::Rbf => self.monitoring.replace_txid(txid, new_txid).await?,
        };

        Ok(new_txid)
    }

    /// A Chunk is valid if:
    /// - It comes from previous L1 blocks
    /// - It comes from the same L1 block
    ///    and its tx appears before its Aggregate tx.
    async fn verify_chunk_order(
        &self,
        block_height: u64,
        tx_id: &Txid,
        chunk_id: &Txid,
        aggregate_idx: usize,
        tx_block_hash: Option<BlockHash>,
        chunks: &HashMap<Txid, usize>,
    ) -> anyhow::Result<()> {
        // If chunk exists, it means it is in the same block as the aggregate
        // Check the order
        if let Some(chunk_idx) = chunks.get(chunk_id) {
            if *chunk_idx >= aggregate_idx {
                // This means the chunk comes after the aggregate in the same block
                // This is not a valid case because lcp expects all chunks to come before their aggregate
                return Err(anyhow!(
                    "{}:{}: Chunk comes after aggregate. Block height: {}",
                    tx_id,
                    chunk_id,
                    block_height,
                ));
            }
        } else {
            // If chunk does not exist, it means it is in a different block
            // Check the block height
            let tx_block_height = if let Some(tx_block_hash) = tx_block_hash {
                self.get_block_height_from_block_hash(tx_block_hash).await?
            } else {
                return Err(anyhow!(
                    "{}:{}: Failed to get block hash for chunk",
                    tx_id,
                    chunk_id
                ));
            };
            if tx_block_height > block_height as usize {
                // This means the chunk comes after the aggregate in a future block
                // This is not a valid case because lcp expects all chunks to come before their aggregate
                return Err(anyhow!(
                    "{}:{}: Chunk comes after aggregate. Block height: {}, Chunk block height: {}",
                    tx_id,
                    chunk_id,
                    block_height,
                    tx_block_height
                ));
            }
        }

        Ok(())
    }

    async fn get_block_height_from_block_hash(
        &self,
        tx_block_hash: BlockHash,
    ) -> anyhow::Result<usize> {
        if let Some(height) = self
            .l1_block_hash_to_height
            .lock()
            .await
            .get(&tx_block_hash)
        {
            return Ok(*height);
        }
        let exponential_backoff = ExponentialBackoff::default();
        let res = retry_backoff(exponential_backoff, || async move {
            self.client
                .get_block_info(&tx_block_hash)
                .await
                .map_err(|e| match e {
                    BitcoinError::Io(_) => backoff::Error::transient(e),
                    _ => backoff::Error::permanent(e),
                })
        })
        .await;
        match res {
            Ok(r) => {
                self.l1_block_hash_to_height
                    .lock()
                    .await
                    .put(tx_block_hash, r.height);
                Ok(r.height)
            }
            Err(e) => Err(anyhow!(
                "Failed to request block by block hash:{:?} Error: {e}",
                tx_block_hash
            )),
        }
    }
}

#[async_trait]
impl DaService for BitcoinService {
    type Spec = BitcoinSpec;

    type Verifier = BitcoinVerifier;

    type FilteredBlock = BitcoinBlock;

    type TransactionId = TxidWrapper;

    type Error = anyhow::Error;

    // Make an RPC call to the node to get the block at the given height
    // If no such block exists, block until one does.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_block_at(&self, height: u64) -> anyhow::Result<Self::FilteredBlock> {
        debug!("Getting block at height {}", height);

        let block_hash;
        loop {
            block_hash = match self.client.get_block_hash(height).await {
                Ok(block_hash_response) => block_hash_response,
                Err(e) => {
                    match e {
                        Error::JsonRpc(RpcError::Rpc(rpc_err)) => {
                            if rpc_err.code == -8 {
                                info!("Block not found, waiting");
                                tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL)).await;
                                continue;
                            } else {
                                // other error, return message
                                bail!(rpc_err.message);
                            }
                        }
                        _ => bail!(e),
                    }
                }
            };

            break;
        }
        let block = self.get_block_by_hash(block_hash.into()).await?;

        Ok(block)
    }

    /// Fetch the [`DaSpec::BlockHeader`] of the last finalized block.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_last_finalized_block_header(
        &self,
    ) -> anyhow::Result<<Self::Spec as DaSpec>::BlockHeader> {
        let block_count = self.client.get_block_count().await?;

        let finalized_blockhash = self
            .client
            .get_block_hash(
                block_count
                    .saturating_sub(self.network_constants.finality_depth)
                    .saturating_add(1),
            )
            .await?;

        let finalized_block_header = self.get_block_by_hash(finalized_blockhash.into()).await?;

        Ok(finalized_block_header.header)
    }

    // Fetch the head block of DA.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_head_block_header(&self) -> anyhow::Result<<Self::Spec as DaSpec>::BlockHeader> {
        let best_blockhash = self.client.get_best_block_hash().await?;

        let head_block_header = self.get_block_by_hash(best_blockhash.into()).await?;

        Ok(head_block_header.header)
    }

    fn decompress_chunks(&self, complete_chunks: &[u8]) -> anyhow::Result<Vec<u8>, Self::Error> {
        BitcoinSpec::decompress_chunks(complete_chunks)
            .map_err(|_| anyhow!("Failed to parse complete chunks"))
    }

    /// Extract zk proofs.
    /// If a proof is stored in an Aggregate (doesn't fit into one tx),
    ///  then the proof is reconstructed from its chunks.
    /// Returns a list of proofs in the order the order of tx they appear in the block.
    async fn extract_relevant_zk_proofs(
        &self,
        block: &Self::FilteredBlock,
        prover_da_pub_key: &[u8],
    ) -> Vec<(usize, Proof)> {
        let mut completes = Vec::new();
        let mut aggregate_idxs = Vec::new();
        let mut chunks = std::collections::HashMap::new();

        for (i, tx) in block.txdata.iter().enumerate() {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.reveal_tx_prefix)
            {
                continue;
            }

            if let Ok(parsed) = parse_relevant_transaction(tx) {
                let tx_id = tx.compute_txid();
                match parsed {
                    ParsedTransaction::Complete(complete) => {
                        if complete.public_key() == prover_da_pub_key
                            && complete.get_sig_verified_hash().is_some()
                        {
                            let Ok(data) = DataOnDa::try_from_slice(&complete.body) else {
                                warn!("{tx_id}: Failed to parse complete data");
                                continue;
                            };

                            let DataOnDa::Complete(compressed_zk_proof) = data else {
                                warn!("{}: Complete: unexpected kind", tx_id);
                                continue;
                            };

                            // push only when signature is correct
                            let Ok(zk_proof) = self.decompress_chunks(&compressed_zk_proof) else {
                                warn!("{tx_id}: Failed to decompress blob");
                                continue;
                            };

                            completes.push((i, zk_proof));
                        }
                    }
                    ParsedTransaction::Aggregate(aggregate) => {
                        if aggregate.public_key() == prover_da_pub_key
                            && aggregate.get_sig_verified_hash().is_some()
                        {
                            // push only when signature is correct
                            // collect tx ids
                            aggregate_idxs.push((i, tx_id, aggregate));
                        }
                    }
                    ParsedTransaction::Chunk(_chunk) => {
                        // This is stored so we can see which chunk has what index
                        // This will help determine which comes first if in the same block aggregate or chunk
                        chunks.insert(tx_id, i);
                    }
                    ParsedTransaction::BatchProverMethodId(_) => {
                        // ignore because these are not proofs
                    }
                    ParsedTransaction::SequencerCommitment(_) => {
                        // ignore
                    }
                }
            }
        }

        // collect aggregated txs from chunks
        let mut aggregates = Vec::new();
        'aggregate: for (aggregate_idx, tx_id, aggregate) in aggregate_idxs {
            let mut body = Vec::new();
            let Ok(data) = DataOnDa::try_from_slice(&aggregate.body) else {
                warn!("{tx_id}: Failed to parse aggregate");
                continue;
            };
            let DataOnDa::Aggregate(chunk_ids, _wtx_ids) = data else {
                error!("{tx_id}: Aggregate: unexpected kind");
                continue;
            };
            if chunk_ids.is_empty() {
                error!("{tx_id}: Empty aggregate tx list");
                continue;
            }
            for chunk_id in chunk_ids {
                let chunk_id = Txid::from_byte_array(chunk_id);
                let exponential_backoff = ExponentialBackoff::default();
                let tx_raw = {
                    let res = retry_backoff(exponential_backoff.clone(), || async move {
                        self.client
                            .get_raw_transaction_info(&chunk_id, None)
                            .await
                            .map_err(|e| match e {
                                BitcoinError::Io(_) => backoff::Error::transient(e),
                                _ => backoff::Error::permanent(e),
                            })
                    })
                    .await;
                    match res {
                        Ok(r) => r,
                        Err(e) => {
                            error!("{}:{}: Failed to request chunk: {e}", tx_id, chunk_id);
                            continue 'aggregate;
                        }
                    }
                };

                if let Err(e) = self
                    .verify_chunk_order(
                        block.header.height,
                        &tx_id,
                        &chunk_id,
                        aggregate_idx,
                        tx_raw.blockhash,
                        &chunks,
                    )
                    .await
                {
                    warn!("{}:{}: Failed to process chunk: {e}", tx_id, chunk_id);
                    continue 'aggregate;
                };

                let chunk_transaction = match tx_raw.transaction() {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!(
                            "{}:{}: Failed to get chunk transaction, decode error: {e}",
                            tx_id, chunk_id
                        );
                        continue 'aggregate;
                    }
                };
                let parsed = match parse_relevant_transaction(&chunk_transaction) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("{}:{}: Failed parse chunk: {e}", tx_id, chunk_id);
                        continue 'aggregate;
                    }
                };
                match parsed {
                    ParsedTransaction::Chunk(part) => {
                        let Ok(data) = DataOnDa::try_from_slice(&part.body) else {
                            warn!("{tx_id}: Failed to parse chunk");
                            continue 'aggregate;
                        };
                        let DataOnDa::Chunk(chunk) = data else {
                            warn!("{tx_id}: Chunk: unexpected kind",);
                            continue 'aggregate;
                        };
                        body.extend(chunk);
                    }
                    ParsedTransaction::Complete(_)
                    | ParsedTransaction::Aggregate(_)
                    | ParsedTransaction::BatchProverMethodId(_)
                    | ParsedTransaction::SequencerCommitment(_) => {
                        error!("{}:{}: Expected chunk, got other tx kind", tx_id, chunk_id);
                        continue 'aggregate;
                    }
                }
            }
            let Ok(zk_proof) = decompress_blob(&body) else {
                warn!("{tx_id}: Failed to decompress blob from Aggregate");
                continue 'aggregate;
            };

            aggregates.push((aggregate_idx, zk_proof));
        }

        let mut proofs: Vec<_> = completes.into_iter().chain(aggregates).collect();
        // restore the order of tx they appear in the block
        proofs.sort_by_key(|b| b.0);

        proofs
    }

    /// Extract SequencerCommitment's from the block
    fn extract_relevant_sequencer_commitments(
        &self,
        block: &Self::FilteredBlock,
        sequencer_da_pub_key: &[u8],
    ) -> Vec<(usize, SequencerCommitment)> {
        let mut sequencer_commitments = Vec::new();

        for (idx, tx) in block.txdata.iter().enumerate() {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.reveal_tx_prefix)
            {
                continue;
            }

            if let Ok(ParsedTransaction::SequencerCommitment(seq_comm)) =
                parse_relevant_transaction(tx)
            {
                if seq_comm.get_sig_verified_hash().is_some()
                    && seq_comm.public_key() == sequencer_da_pub_key
                {
                    let data = DataOnDa::try_from_slice(&seq_comm.body);
                    if let Ok(DataOnDa::SequencerCommitment(seq_com)) = data {
                        sequencer_commitments.push((idx, seq_com));
                    }
                }
            } else {
                // ignore
            }
        }
        sequencer_commitments
    }

    /// Extract the relevant transactions from a block, along with a proof that the extraction has been done correctly.
    /// For example, this method might return all of the blob transactions in rollup's namespace,
    /// together with a range proof against the root of the namespaced-merkle-tree, demonstrating that the entire
    /// rollup namespace has been covered.
    #[allow(clippy::type_complexity)]
    fn extract_relevant_blobs_with_proof(
        &self,
        block: &Self::FilteredBlock,
    ) -> (
        Vec<<Self::Spec as DaSpec>::BlobTransaction>,
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    ) {
        info!(
            "Getting extraction proof for block {:?}",
            block.header.block_hash()
        );

        let prefix = self.reveal_tx_prefix.as_slice();

        let mut completeness_proof = Vec::with_capacity(block.txdata.len());

        let mut wtxids = Vec::with_capacity(block.txdata.len());
        wtxids.push([0u8; 32]);

        // coinbase starts with 0, so we skip it unless the prefix is all 0's
        if prefix.iter().all(|&x| x == 0) {
            completeness_proof.push(block.txdata[0].clone());
        }

        block.txdata[1..].iter().for_each(|tx| {
            let wtxid = tx.compute_wtxid().to_raw_hash().to_byte_array();

            // if tx_hash starts with the given prefix, it is in the completeness proof
            if wtxid.starts_with(prefix) {
                completeness_proof.push(tx.clone());
            }

            wtxids.push(wtxid);
        });

        let txid_merkle_tree = merkle_tree::BitcoinMerkleTree::new(
            block
                .txdata
                .iter()
                .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
                .collect(),
        );

        assert_eq!(
            txid_merkle_tree.root(),
            block.header.merkle_root(),
            "Merkle root mismatch"
        );

        let coinbase_proof = txid_merkle_tree.get_idx_path(0);
        let inclusion_proof =
            InclusionMultiProof::new(wtxids, block.txdata[0].clone(), coinbase_proof);

        let mut relevant_txs = vec![];
        for tx in &completeness_proof {
            let wtxid = tx.compute_wtxid();
            if let Ok(tx) = parse_relevant_transaction(tx) {
                match tx {
                    ParsedTransaction::Complete(complete) => {
                        if let Some(hash) = complete.get_sig_verified_hash() {
                            // complete.body is compressed, but we'll leave the compression to
                            // circuit logic
                            let relevant_tx = BlobWithSender::new(
                                complete.body,
                                complete.public_key,
                                hash,
                                wtxid.to_byte_array(),
                            );
                            relevant_txs.push(relevant_tx);
                        }
                    }
                    ParsedTransaction::Aggregate(aggregate) => {
                        if let Some(hash) = aggregate.get_sig_verified_hash() {
                            let relevant_tx = BlobWithSender::new(
                                aggregate.body,
                                aggregate.public_key,
                                hash,
                                wtxid.to_byte_array(),
                            );
                            relevant_txs.push(relevant_tx);
                        }
                    }
                    ParsedTransaction::Chunk(chunk) => {
                        let relevant_tx =
                            BlobWithSender::new(chunk.body, vec![], [0; 32], wtxid.to_byte_array());
                        relevant_txs.push(relevant_tx);
                    }
                    ParsedTransaction::BatchProverMethodId(method_id) => {
                        if let Some(hash) = method_id.get_sig_verified_hash() {
                            let relevant_tx = BlobWithSender::new(
                                method_id.body,
                                method_id.public_key,
                                hash,
                                wtxid.to_byte_array(),
                            );
                            relevant_txs.push(relevant_tx);
                        }
                    }
                    ParsedTransaction::SequencerCommitment(seq_comm) => {
                        if let Some(hash) = seq_comm.get_sig_verified_hash() {
                            let relevant_tx = BlobWithSender::new(
                                seq_comm.body,
                                seq_comm.public_key,
                                hash,
                                wtxid.to_byte_array(),
                            );

                            relevant_txs.push(relevant_tx);
                        }
                    }
                }
            }
        }

        (relevant_txs, inclusion_proof, completeness_proof)
    }

    #[instrument(level = "trace", skip_all)]
    async fn send_transaction(
        &self,
        tx_request: DaTxRequest,
    ) -> anyhow::Result<<Self as DaService>::TransactionId> {
        let queue = self.get_send_transaction_queue();
        let (tx, rx) = oneshot_channel();
        queue.send(TxRequestWithNotifier {
            tx_request,
            notify: tx,
        })?;
        rx.await?
    }

    fn get_send_transaction_queue(
        &self,
    ) -> UnboundedSender<TxRequestWithNotifier<Self::TransactionId>> {
        self.inscribes_queue.clone()
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_fee_rate(&self) -> anyhow::Result<u128> {
        let sat_vb_ceil = self.fee.get_fee_rate_as_sat_vb().await? as u128;

        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000 for BTC to CBTC conversion (decimals)
        let multiplied_fee = sat_vb_ceil.saturating_mul(2_500_000_000);
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(
        &self,
        hash: <Self::Spec as DaSpec>::SlotHash,
    ) -> anyhow::Result<Self::FilteredBlock> {
        let hash = hash.0;
        debug!("Getting block with hash {:?}", hash);

        let block = self.client.get_block_verbose(&hash).await?;

        let header: Header = Header {
            bits: CompactTarget::from_unprefixed_hex(&block.bits)?,
            merkle_root: block.merkleroot,
            nonce: block.nonce,
            prev_blockhash: block.previousblockhash.unwrap_or_else(BlockHash::all_zeros),
            time: block.time as u32,
            version: block.version,
        };

        let txs = block
            .tx
            .iter()
            .map(|tx| {
                Transaction::consensus_decode(&mut &tx.hex[..])
                    .map(|transaction| transaction.into())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let tx_count = txs.len();

        let witness_root = calculate_witness_root(&txs, tx_count);

        Ok(BitcoinBlock {
            header: HeaderWrapper::new(header, tx_count as u32, block.height, witness_root),
            txdata: txs,
        })
    }

    fn block_to_short_header_proof(
        block: Self::FilteredBlock,
    ) -> <Self::Spec as DaSpec>::ShortHeaderProof {
        let header = block.header;
        // Build txid merkle tree

        let txids = block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().as_raw_hash().to_byte_array())
            .collect::<Vec<_>>();

        let txid_merkle_tree = BitcoinMerkleTree::new(txids);

        let txid_merkle_proof = txid_merkle_tree.get_idx_path(0);

        let coinbase_tx = block.txdata[0].clone();

        // sanity check
        assert_eq!(
            merkle_tree::BitcoinMerkleTree::calculate_root_with_merkle_proof(
                coinbase_tx.compute_txid().as_raw_hash().to_byte_array(),
                0,
                &txid_merkle_proof
            ),
            header.merkle_root()
        );

        BitcoinHeaderShortProof::new(header, coinbase_tx, txid_merkle_proof)
    }

    async fn get_pending_sequencer_commitments(
        &self,
        sequencer_da_pub_key: &[u8],
    ) -> Vec<SequencerCommitment> {
        let pending_txs = self.get_pending_transactions().await;

        let mut sequencer_commitments = Vec::new();

        for tx in &pending_txs {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.reveal_tx_prefix)
            {
                continue;
            }

            if let Ok(ParsedTransaction::SequencerCommitment(seq_comm)) =
                parse_relevant_transaction(tx)
            {
                // we check on da pending txs of our wallet however let's keep consistency
                if seq_comm.get_sig_verified_hash().is_some()
                    && seq_comm.public_key == sequencer_da_pub_key
                {
                    let da_data = DataOnDa::try_from_slice(&seq_comm.body);
                    match da_data {
                        Ok(da_data) => match da_data {
                            DataOnDa::SequencerCommitment(commitment) => {
                                sequencer_commitments.push(commitment);
                            }
                            _ => {
                                // ignore
                            }
                        },
                        Err(err) => {
                            warn!("Pending transaction blob failed to be parsed: {}", err);
                        }
                    }
                }
            } else {
                // ignore
            }
        }
        sequencer_commitments
    }
}

/// Wrapper around Txid to be used in DaSpec.
#[derive(PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxidWrapper(Txid);
impl From<TxidWrapper> for [u8; 32] {
    fn from(val: TxidWrapper) -> Self {
        val.0.to_byte_array()
    }
}

/// This function splits Proof based on its size. It is either:
/// 1: borsh(DataOnDa::Complete(compress(Proof)))
/// 2:
///   let compressed = compress(Proof)
///   let chunks = compressed.chunks(MAX_TX_BODY_SIZE)
///   [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
pub(crate) fn split_proof(zk_proof: Proof) -> anyhow::Result<RawTxData> {
    let original_compressed = compress_blob(&zk_proof)?;

    if original_compressed.len() < MAX_TX_BODY_SIZE {
        let data = DataOnDa::Complete(original_compressed);
        let blob = borsh::to_vec(&data).expect("zk::Proof serialize must not fail");
        Ok(RawTxData::Complete(blob))
    } else {
        let mut chunks = vec![];
        for chunk in original_compressed.chunks(MAX_TX_BODY_SIZE) {
            let data = DataOnDa::Chunk(chunk.to_vec());
            let blob = borsh::to_vec(&data).expect("zk::Proof Chunk serialize must not fail");
            chunks.push(blob)
        }

        Ok(RawTxData::Chunks(chunks))
    }
}

/// Compute the witness merkle root of txs.
fn calculate_witness_root(txdata: &[TransactionWrapper], tx_count: usize) -> [u8; 32] {
    // If there is only one transaction in the block, the witness root is all zeros
    // So the merkle root is all zeros as well
    if tx_count == 1 {
        return [0u8; 32];
    }

    let hashes = txdata
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == 0 {
                let commitment_idx = t.output.iter().rposition(|output| {
                    output.script_pubkey.as_bytes().len() >= MINIMUM_WITNESS_COMMITMENT_SIZE
                        && output
                            .script_pubkey
                            .as_bytes()
                            .starts_with(WITNESS_COMMITMENT_PREFIX)
                });
                // If non-segwit block, the coinbase tx should also use the txid instead of all zeros
                match commitment_idx {
                    Some(_) => Wtxid::all_zeros().to_raw_hash().to_byte_array(),
                    None => t.compute_wtxid().to_raw_hash().to_byte_array(),
                }
            } else {
                t.compute_wtxid().to_raw_hash().to_byte_array()
            }
        })
        .collect();
    BitcoinMerkleTree::new(hashes).root()
}
