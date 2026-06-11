//! This module provides the Bitcoin DA service implementation.

// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::time::Duration;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Transaction, Txid, Wtxid};
use bitcoincore_rpc::{Client, Error as BitcoinError, Error, RpcApi, RpcError};
use borsh::BorshDeserialize;
use citrea_common::utils::read_env;
use citrea_primitives::compression::decompress_blob;
use citrea_primitives::MAX_COMPRESSED_BLOB_SIZE;
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

use crate::error::BitcoinServiceError;
use crate::fee::FeeService;
use crate::helpers::merkle_tree;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use crate::monitoring::{MonitoringConfig, MonitoringService, TxStatus};
use crate::network_constants::NetworkConstants;
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::short_proof::BitcoinHeaderShortProof;
use crate::spec::transaction::TransactionWrapper;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::tx_sender::{
    bitcoin_status_to_monitoring, queue_tx_sender_request, wait_for_tx_sender_job,
};
use crate::verifier::{
    BitcoinVerifier, MINIMUM_WITNESS_COMMITMENT_SIZE, WITNESS_COMMITMENT_PREFIX,
};

pub(crate) type Result<T> = std::result::Result<T, BitcoinServiceError>;

const POLLING_INTERVAL: u64 = 10; // seconds

/// How often we poll the external tx-sender for job status.
///
/// This drives how quickly the local monitoring state is synced with the
/// transactions the tx-sender builds and broadcasts on our behalf. The
/// tx-sender itself advances its jobs on a ~1s cadence, so we poll at the same
/// rate to keep monitoring (pending transactions, tx status) responsive instead
/// of lagging by up to a full block-polling interval.
const TX_SENDER_POLL_INTERVAL: u64 = 1; // seconds

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

    /// Monitoring configuration.
    pub monitoring: Option<MonitoringConfig>,
    /// The URL of the mempool.space API.
    /// It should end with a slash.
    /// It should include the network but not api
    /// So for mainnet: https://mempool.space/
    /// For testnet: https://mempool.space/testnet4/
    pub mempool_space_url: Option<String>,

    /// Timeout for RPC requests in seconds
    pub rpc_timeout_secs: Option<u64>,

    /// Connection timeout for RPC in seconds
    pub rpc_connect_timeout_secs: Option<u64>,

    /// URL of the external tx-sender service.
    pub tx_sender_url: Option<String>,
}

impl citrea_common::FromEnv for BitcoinServiceConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            node_url: read_env("NODE_URL")?,
            node_username: read_env("NODE_USERNAME")?,
            node_password: read_env("NODE_PASSWORD")?,
            monitoring: MonitoringConfig::from_env().ok(),
            mempool_space_url: read_env("MEMPOOL_SPACE_URL").ok(),
            rpc_timeout_secs: read_env("BITCOIN_RPC_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok()),
            rpc_connect_timeout_secs: read_env("BITCOIN_RPC_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok()),
            tx_sender_url: read_env("TX_SENDER_URL").ok(),
        })
    }
}

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug)]
pub struct BitcoinService {
    client: Arc<Client>,
    #[allow(dead_code)]
    pub(crate) network: bitcoin::Network,
    network_constants: NetworkConstants,
    pub(crate) reveal_tx_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxSenderJobId>>,
    /// Monitoring service for tracking transaction status.
    pub monitoring: Arc<MonitoringService>,
    fee: FeeService,
    l1_block_hash_to_height: Arc<Mutex<LruCache<BlockHash, usize>>>,
    tx_sender: Option<tx_sender_jsonrpc_client::JsonRpcTxSenderClient>,
}

impl BitcoinService {
    pub(crate) async fn get_monitored_tx_status(
        &self,
        txid: Txid,
    ) -> Option<crate::monitoring::TxStatus> {
        if let Some(status) = self.monitoring.get_tx_status(&txid).await {
            return Some(status);
        }

        if let Some(tx_sender) = self.tx_sender.clone() {
            let response = tx_sender
                .track_tx(tx_sender_jsonrpc_client::TrackRequest::ByTxid {
                    txid: txid.to_string(),
                })
                .await
                .ok();

            if let Some(tx_sender_jsonrpc_client::TrackResponse::Transaction(status)) = response {
                if let Some(status) = bitcoin_status_to_monitoring(
                    &self.client,
                    self.network_constants.finality_depth,
                    &status.tx_info,
                    status.fee_sat_kvb,
                )
                .await
                {
                    return Some(status);
                }
            }
        }

        self.get_bitcoin_node_status(txid).await
    }

    async fn get_bitcoin_node_status(&self, txid: Txid) -> Option<crate::monitoring::TxStatus> {
        if let Ok(entry) = self.client.get_mempool_entry(&txid).await {
            return Some(crate::monitoring::TxStatus::InMempool {
                base_fee: entry.fees.base.to_sat() as f64 / entry.vsize as f64,
                timestamp: entry.time,
                height: entry.height,
            });
        }

        let info = self
            .client
            .get_raw_transaction_info(&txid, None)
            .await
            .ok()?;
        let block_hash = info.blockhash?;
        let confirmations = u64::from(info.confirmations?);
        let block_height = self
            .client
            .get_block_header_info(&block_hash)
            .await
            .ok()?
            .height as u64;

        if confirmations >= self.network_constants.finality_depth {
            Some(crate::monitoring::TxStatus::Finalized {
                block_hash,
                block_height,
                confirmations,
            })
        } else {
            Some(crate::monitoring::TxStatus::Confirmed {
                block_hash,
                block_height,
                confirmations,
            })
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
        inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxSenderJobId>>,
    ) -> Result<Self> {
        let tx_sender = match (require_wallet_check, config.tx_sender_url.as_deref()) {
            (true, Some(url)) => {
                info!("Initializing external tx-sender client at {url}");
                Some(
                    tx_sender_jsonrpc_client::JsonRpcTxSenderClient::new(url)
                        .map_err(|e| BitcoinServiceError::Other(anyhow::anyhow!(e)))?,
                )
            }
            (true, None) => {
                return Err(BitcoinServiceError::Other(anyhow::anyhow!(
                    "TX_SENDER_URL is required when wallet checks are enabled"
                )));
            }
            (false, _) => None,
        };

        Ok(Self {
            client: client.clone(),
            network,
            network_constants,
            reveal_tx_prefix: chain_params.reveal_tx_prefix,
            inscribes_queue,
            monitoring,
            fee: fee_service,
            l1_block_hash_to_height: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(100).unwrap(),
            ))),
            tx_sender,
        })
    }

    /// Run the task to process the DA commands from the queue.
    #[instrument(name = "BitcoinDA", skip_all)]
    pub async fn run_da_queue(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<TxRequestWithNotifier<TxSenderJobId>>,
        mut new_block_rx: UnboundedReceiver<u64>,
        mut shutdown: GracefulShutdown,
    ) {
        trace!("BitcoinDA queue is initialized. Waiting for the first request...");

        loop {
            select! {
                biased;
                _ = &mut shutdown => {
                    debug!("DA queue service received shutdown signal");
                    break;
                }
                new_height_opt = new_block_rx.recv() => {
                    if let Some(new_height) = new_height_opt {
                        trace!("New da block height {new_height}. No local DA queue processing is required in tx-sender mode.");
                    }
                }
                request_opt = rx.recv() => {
                    if let Some(request) = request_opt {
                        trace!("A new request is received");
                        let Some(tx_sender) = self.tx_sender.clone() else {
                            error!("DA queue received a request without an initialized tx-sender client");
                            let _ = request.notify.send(Err(anyhow::anyhow!(
                                "tx-sender client is not configured"
                            )));
                            continue;
                        };
                        queue_tx_sender_request(
                            tx_sender,
                            self.client.clone(),
                            self.monitoring.clone(),
                            request,
                            Duration::from_secs(TX_SENDER_POLL_INTERVAL),
                            &mut shutdown,
                        )
                        .await;
                    }
                }
            }
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_pending_transactions(&self) -> Vec<Transaction> {
        // Discover any relevant txs the tx-sender has broadcast on our behalf but
        // that monitoring hasn't observed yet, so the pending view reflects the
        // mempool without waiting for a tx-sender poll cycle.
        if let Err(e) = self.monitoring.sync_pending_from_wallet().await {
            debug!("Failed to sync pending transactions from wallet: {e}");
        }

        self.monitoring
            .get_monitored_txs()
            .await
            .into_iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::InMempool { .. }))
            .map(|(_, monitored_tx)| monitored_tx.tx)
            .collect()
    }

    /// A Chunk is valid if:
    /// - It comes from previous L1 blocks
    /// - It comes from the same L1 block
    ///   and its tx appears before its Aggregate tx.
    async fn verify_chunk_order(
        &self,
        block_height: u64,
        tx_id: &Txid,
        chunk_id: &Txid,
        aggregate_idx: usize,
        tx_block_hash: Option<BlockHash>,
        chunks: &HashMap<Txid, usize>,
    ) -> Result<()> {
        // If chunk exists, it means it is in the same block as the aggregate
        // Check the order
        if let Some(chunk_idx) = chunks.get(chunk_id) {
            if *chunk_idx >= aggregate_idx {
                // This means the chunk comes after the aggregate in the same block
                // This is not a valid case because lcp expects all chunks to come before their aggregate
                return Err(BitcoinServiceError::ChunkOrderingError(format!(
                    "{tx_id}:{chunk_id}: Chunk comes after aggregate. Block height: {block_height}",
                )));
            }
        } else {
            // If chunk does not exist, it means it is in a different block
            // Check the block height
            let tx_block_height = if let Some(tx_block_hash) = tx_block_hash {
                self.get_block_height_from_block_hash(tx_block_hash).await?
            } else {
                return Err(BitcoinServiceError::ChunkOrderingError(format!(
                    "{tx_id}:{chunk_id}: Failed to get block hash for chunk"
                )));
            };
            if tx_block_height > block_height as usize {
                // This means the chunk comes after the aggregate in a future block
                // This is not a valid case because lcp expects all chunks to come before their aggregate
                return Err(BitcoinServiceError::ChunkOrderingError(format!(
                    "{tx_id}:{chunk_id}: Chunk comes after aggregate. Block height: {block_height}, Chunk block height: {tx_block_height}"
                )));
            }
        }

        Ok(())
    }

    async fn get_block_height_from_block_hash(&self, tx_block_hash: BlockHash) -> Result<usize> {
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
            Err(e) => Err(BitcoinServiceError::BlockInfoRequestError {
                hash: tx_block_hash,
                source: e,
            }),
        }
    }
}

#[async_trait]
impl DaService for BitcoinService {
    type Spec = BitcoinSpec;

    type Verifier = BitcoinVerifier;

    type FilteredBlock = BitcoinBlock;

    type TransactionId = TxidWrapper;
    type SubmissionId = TxSenderJobId;

    type Error = BitcoinServiceError;

    // Make an RPC call to the node to get the block at the given height
    // If no such block exists, block until one does.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock> {
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
                                return Err(BitcoinServiceError::RpcError(Error::JsonRpc(
                                    RpcError::Rpc(rpc_err),
                                )));
                            }
                        }
                        _ => return Err(BitcoinServiceError::RpcError(e)),
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
    async fn get_last_finalized_block_header(&self) -> Result<<Self::Spec as DaSpec>::BlockHeader> {
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
    async fn get_head_block_header(&self) -> Result<<Self::Spec as DaSpec>::BlockHeader> {
        let best_blockhash = self.client.get_best_block_hash().await?;

        let head_block_header = self.get_block_by_hash(best_blockhash.into()).await?;

        Ok(head_block_header.header)
    }

    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>> {
        BitcoinSpec::decompress_chunks(complete_chunks)
            .map_err(|_| BitcoinServiceError::ChunkDecompressionError)
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
                            tracing::info!("Found complete tx with tx id: {}", tx_id);
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
                            tracing::info!("Found aggregate tx with tx id: {}", tx_id);
                            // push only when signature is correct
                            // collect tx ids
                            aggregate_idxs.push((i, tx_id, aggregate));
                        }
                    }
                    ParsedTransaction::Chunk(_chunk) => {
                        // This is stored so we can see which chunk has what index
                        // This will help determine which comes first if in the same block aggregate or chunk
                        tracing::info!("Found chunk tx with tx id: {}", tx_id);
                        chunks.insert(tx_id, i);
                    }
                    ParsedTransaction::BatchProofMethodId(_) => {
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

                        if chunk.len() + body.len() > MAX_COMPRESSED_BLOB_SIZE {
                            warn!("{tx_id}: Compressed aggregate too large");
                            continue 'aggregate;
                        }

                        body.extend(chunk);
                    }
                    ParsedTransaction::Complete(_)
                    | ParsedTransaction::Aggregate(_)
                    | ParsedTransaction::BatchProofMethodId(_)
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
                    ParsedTransaction::BatchProofMethodId(method_id) => {
                        // Pubkey here is given as 0 because the security council pub keys are inside the body
                        let public_key = [0u8; 32].to_vec();
                        let hash = method_id.hash();

                        let relevant_tx = BlobWithSender::new(
                            // Body here is: borsh(DataOnDa::BatchProofMethodId(BatchProofMethodId { ... }))
                            // The sender field here is not used because this transaction has a security council
                            // consisting of 5 public keys, this data and signatures are embedded in the body
                            method_id.body,
                            public_key,
                            hash,
                            wtxid.to_byte_array(),
                        );
                        relevant_txs.push(relevant_tx);
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
    ) -> Result<<Self as DaService>::SubmissionId> {
        let queue = self.get_send_transaction_queue();
        let (tx, rx) = oneshot_channel();
        queue
            .send(TxRequestWithNotifier {
                tx_request,
                notify: tx,
            })
            .map_err(|_| BitcoinServiceError::ChannelSendError)?;
        rx.await?.map_err(BitcoinServiceError::Other)
    }

    async fn wait_for_transaction_id(
        &self,
        submission_id: Self::SubmissionId,
    ) -> Result<Self::TransactionId> {
        let Some(tx_sender) = self.tx_sender.clone() else {
            return Err(BitcoinServiceError::Other(anyhow::anyhow!(
                "tx-sender client is not configured"
            )));
        };

        let txid = wait_for_tx_sender_job(
            tx_sender,
            self.client.clone(),
            self.monitoring.clone(),
            submission_id.0,
            Duration::from_secs(TX_SENDER_POLL_INTERVAL),
        )
        .await
        .map_err(BitcoinServiceError::Other)?;

        Ok(TxidWrapper(txid))
    }

    fn get_send_transaction_queue(
        &self,
    ) -> UnboundedSender<TxRequestWithNotifier<Self::SubmissionId>> {
        self.inscribes_queue.clone()
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_fee_rate(&self) -> Result<u128> {
        let sat_vb = self
            .fee
            .get_fee_rate()
            .await
            .map_err(|_| BitcoinServiceError::FeeRateError)?;

        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000 for BTC to CBTC conversion (decimals)
        // if somehow the value is out of bounds, return a default fee rate of 1 BTC/vB
        let sat_vb = (sat_vb * 2_500_000_000f64).ceil();
        let multiplied_fee = f64_to_u128(sat_vb).unwrap_or_else(|| {
            warn!(
                "Fee rate {} out of bounds, returning default fee rate of 1 CBTC/vB",
                sat_vb
            );
            2_500_000_000
        });
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(
        &self,
        hash: <Self::Spec as DaSpec>::SlotHash,
    ) -> Result<Self::FilteredBlock> {
        let hash = hash.0;
        debug!("Getting block with hash {:?}", hash);

        let block = self.client.get_block(&hash).await?;

        // Safe to use `bip34_block_height` within citrea constraints:
        // - Mainnet start height is 924022, past BIP-34 activation height of 227835.
        // - Testnet4 started after BIP-34 activation.
        // - Only working on finalized blocks so any invalid BIP-34 block would have been rejected by Bitcoin consensus
        let height = match block.bip34_block_height() {
            Ok(height) => height,
            Err(_) => self.client.get_block_header_info(&hash).await?.height as u64,
        };

        let txs = block.txdata.into_iter().map(Into::into).collect::<Vec<_>>();
        let tx_count = txs.len();

        let witness_root = calculate_witness_root(&txs, tx_count);

        Ok(BitcoinBlock {
            header: HeaderWrapper::new(block.header, tx_count as u32, height, witness_root),
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxidWrapper(pub(crate) Txid);

/// Wrapper around tx-sender job id to be used as a submission handle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxSenderJobId(pub(crate) i64);

impl From<TxidWrapper> for [u8; 32] {
    fn from(val: TxidWrapper) -> Self {
        val.0.to_byte_array()
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

/// Safely converts f64 to u128, returning None for invalid inputs.
///
/// Returns `None` if:
/// - `x` is NaN or infinite
/// - `x` is negative
/// - `x` >= 2^128 (would overflow u128)
fn f64_to_u128(x: f64) -> Option<u128> {
    // Note: (u128::MAX as f64) rounds up to 2^128 because f64 only has 53 bits
    // of mantissa. We use strict less-than to reject values that would overflow.
    if x.is_finite() && x >= 0.0 && x < (u128::MAX as f64) {
        Some(x as u128)
    } else {
        None
    }
}
