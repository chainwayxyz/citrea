// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::blockdata::script;
use bitcoin::consensus::{encode, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    Wtxid,
};
use bitcoincore_rpc::json::TestMempoolAcceptResult;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi, RpcError};
use borsh::BorshDeserialize;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::MAX_TXBODY_SIZE;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{
    DaData, DaDataBatchProof, DaDataLightClient, DaNamespace, DaSpec, SequencerCommitment,
};
use sov_rollup_interface::services::da::{DaService, SenderWithNotifier};
use sov_rollup_interface::zk::Proof;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::helpers::builders::batch_proof_namespace::{
    create_seqcommitment_transactions, BatchProvingTxs,
};
use crate::helpers::builders::light_client_proof_namespace::{
    create_zkproof_transactions, LightClientTxs, RawLightClientData,
};
use crate::helpers::builders::{TxListWithReveal, TxWithId};
use crate::helpers::merkle_tree;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{
    parse_batch_proof_transaction, parse_light_client_transaction, ParsedBatchProofTransaction,
    ParsedLightClientTransaction, VerifyParsed,
};
use crate::monitoring::{MonitoringConfig, MonitoringService, TxStatus};
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::header_stream::BitcoinHeaderStream;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::transaction::TransactionWrapper;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::verifier::BitcoinVerifier;
use crate::REVEAL_OUTPUT_AMOUNT;

pub const FINALITY_DEPTH: u64 = 8; // blocks
const POLLING_INTERVAL: u64 = 10; // seconds

const MEMPOOL_SPACE_URL: &str = "https://mempool.space/";
const MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT: &str = "api/v1/fees/recommended";

/// Runtime configuration for the DA service
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BitcoinServiceConfig {
    /// The URL of the Bitcoin node to connect to
    pub node_url: String,
    pub node_username: String,
    pub node_password: String,

    // network of the bitcoin node
    pub network: bitcoin::Network,

    // da private key of the sequencer
    pub da_private_key: Option<String>,

    // absolute path to the directory where the txs will be written to
    pub tx_backup_dir: String,

    pub monitoring: Option<MonitoringConfig>,
}

impl citrea_common::FromEnv for BitcoinServiceConfig {
    fn from_env() -> Result<Self> {
        Ok(Self {
            node_url: std::env::var("NODE_URL")?,
            node_username: std::env::var("NODE_USERNAME")?,
            node_password: std::env::var("NODE_PASSWORD")?,
            network: serde_json::from_str(&format!("\"{}\"", std::env::var("NETWORK")?))?,
            da_private_key: std::env::var("DA_PRIVATE_KEY").ok(),
            tx_backup_dir: std::env::var("TX_BACKUP_DIR")?,
            monitoring: Some(MonitoringConfig {
                check_interval: std::env::var("DA_MONITORING_CHECK_INTERVAL")?.parse()?,
                history_limit: std::env::var("DA_MONITORING_HISTORY_LIMIT")?.parse()?,
                max_history_size: std::env::var("DA_MONITORING_MAX_HISTORY_SIZE")?.parse()?,
            }),
        })
    }
}
/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug)]
pub struct BitcoinService {
    client: Arc<Client>,
    network: bitcoin::Network,
    da_private_key: Option<SecretKey>,
    to_light_client_prefix: Vec<u8>,
    to_batch_proof_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
    tx_backup_dir: PathBuf,
    pub monitoring: Arc<MonitoringService>,
}

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub async fn new_with_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
    ) -> Result<Self> {
        let client = Arc::new(
            Client::new(
                &config.node_url,
                Auth::UserPass(config.node_username, config.node_password),
            )
            .await?,
        );

        let private_key = config
            .da_private_key
            .map(|pk| SecretKey::from_str(&pk))
            .transpose()
            .context("Invalid private key")?;

        let wallets = client
            .list_wallets()
            .await
            .expect("Failed to list loaded wallets");

        if wallets.is_empty() {
            tracing::warn!("No loaded wallet found!");
        }

        let tx_backup_dir = std::path::Path::new(&config.tx_backup_dir);

        if !tx_backup_dir.exists() {
            std::fs::create_dir_all(tx_backup_dir)
                .context("Failed to create tx backup directory")?;
        }

        let monitoring = Arc::new(MonitoringService::new(client.clone(), config.monitoring));

        Ok(Self {
            client,
            network: config.network,
            da_private_key: private_key,
            to_light_client_prefix: chain_params.to_light_client_prefix,
            to_batch_proof_prefix: chain_params.to_batch_proof_prefix,
            inscribes_queue: tx,
            tx_backup_dir: tx_backup_dir.to_path_buf(),
            monitoring,
        })
    }

    pub async fn new_without_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
    ) -> Result<Self> {
        let client = Arc::new(
            Client::new(
                &config.node_url,
                Auth::UserPass(config.node_username, config.node_password),
            )
            .await?,
        );

        let da_private_key = config
            .da_private_key
            .map(|pk| SecretKey::from_str(&pk))
            .transpose()
            .context("Invalid private key")?;

        // check if config.tx_backup_dir exists
        let tx_backup_dir = std::path::Path::new(&config.tx_backup_dir);

        if !tx_backup_dir.exists() {
            std::fs::create_dir_all(tx_backup_dir)
                .context("Failed to create tx backup directory")?;
        }

        let monitoring = Arc::new(MonitoringService::new(client.clone(), config.monitoring));

        Ok(Self {
            client,
            network: config.network,
            da_private_key,
            to_light_client_prefix: chain_params.to_light_client_prefix,
            to_batch_proof_prefix: chain_params.to_batch_proof_prefix,
            inscribes_queue: tx,
            tx_backup_dir: tx_backup_dir.to_path_buf(),
            monitoring,
        })
    }

    pub async fn run_da_queue(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<SenderWithNotifier<TxidWrapper>>,
        token: CancellationToken,
    ) {
        let mut prev_utxo = match self.get_prev_utxo().await {
            Ok(Some(prev_utxo)) => Some(prev_utxo),
            Ok(None) => {
                info!("No pending transactions found");
                None
            }
            Err(e) => {
                error!(?e, "Failed to get pending transactions");
                None
            }
        };

        trace!("BitcoinDA queue is initialized. Waiting for the first request...");

        loop {
            select! {
            biased;
            _ = token.cancelled() => {
                debug!("DA queue service received shutdown signal");
                break;
            }
            request_opt = rx.recv() => {
                if let Some(request) = request_opt {
                            trace!("A new request is received");
                            let prev = prev_utxo.take();
                            loop {
                                // Build and send tx with retries:
                                let fee_sat_per_vbyte = match self.get_fee_rate().await {
                                    Ok(rate) => rate,
                                    Err(e) => {
                                        error!(?e, "Failed to call get_fee_rate. Retrying...");
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                        continue;
                                    }
                                };
                                match self
                                    .send_transaction_with_fee_rate(
                                        prev.clone(),
                                        request.da_data.clone(),
                                        fee_sat_per_vbyte,
                                    )
                                    .await
                                {
                                    Ok((txids, tx)) => {
                                        let tx_id = TxidWrapper(tx.id);
                                        info!(%tx.id, "Sent tx to BitcoinDA");
                                        prev_utxo = Some(UTXO {
                                            tx_id: tx.id,
                                            vout: 0,
                                            script_pubkey: tx.tx.output[0].script_pubkey.to_hex_string(),
                                            address: None,
                                            amount: tx.tx.output[0].value.to_sat(),
                                            confirmations: 0,
                                            spendable: true,
                                            solvable: true,
                                        });
                                        let _ = request.notify.send(Ok(tx_id));

                                        if let Err(e) = self.monitoring.monitor_transaction_chain(txids).await {
                                            error!(?e, "Failed to monitor tx chain");
                                        }
                                    }
                                    Err(e) => {
                                        error!(?e, "Failed to send transaction to DA layer");
                                        tokio::time::sleep(Duration::from_secs(1)).await;
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

    /// Retrieves the most recent spendable UTXO from the transaction chain on startup.
    /// `get_prev_utxo` is called on service startup in `spawn_da_queue`.
    /// On very first startup, return any most recent UTXO.
    /// Any subsequent startup would return latest reveal TX first output.
    /// Sorts by (confirmations - ancestor_count), where lower values indicate more recent transactions.
    #[instrument(level = "trace", skip_all, ret)]
    async fn get_prev_utxo(&self) -> Result<Option<UTXO>> {
        let mut previous_utxos = self
            .client
            .list_unspent(Some(0), None, None, Some(true), None)
            .await?;

        // Make sure to retain only first utxo to keep utxo chaining logic in line with `spawn_da_queue` inner loop
        previous_utxos.retain(|u| u.spendable && u.solvable && u.vout == 0);

        // Sort by (confirmations - ancestor_count)
        // If any tx in mempool, confirmation would be 0 and ancestor count Some(_), giving us a negative value and prioritising in-mempool TXs
        // If no tx in mempool, confirmation would be >= 0 and ancestor count None
        previous_utxos.sort_unstable_by_key(|utxo| {
            utxo.confirmations as i64 - (utxo.ancestor_count.unwrap_or(0) as i64)
        });

        Ok(previous_utxos.into_iter().next().map(|u| u.into()))
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_utxos(&self) -> Result<Vec<UTXO>> {
        let utxos = self
            .client
            .list_unspent(Some(0), None, None, None, None)
            .await?;
        if utxos.is_empty() {
            bail!("There are no UTXOs");
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
            bail!("There are no spendable UTXOs");
        }

        Ok(utxos)
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_pending_transactions(&self) -> Vec<Transaction> {
        self.monitoring
            .get_pending_transactions()
            .await
            .into_iter()
            .map(|(_, monitored_tx)| monitored_tx.tx)
            .collect()
    }

    #[instrument(level = "trace", fields(prev_utxo), ret, err)]
    pub async fn send_transaction_with_fee_rate(
        &self,
        mut prev_utxo: Option<UTXO>,
        da_data: DaData,
        fee_sat_per_vbyte: u64,
    ) -> Result<(Vec<Txid>, TxWithId)> {
        let network = self.network;

        let da_private_key = self.da_private_key.expect("No private key set");

        // get all available utxos
        let utxos = self.get_utxos().await?;

        // If Utxo has already been spent, fallback to get_prev_utxo
        // Would happen in case of cpfp spending reveal output
        if let Some(prev) = &prev_utxo {
            if !utxos.iter().any(|utxo| utxo == prev) {
                prev_utxo = self.get_prev_utxo().await?;
            }
        }

        // get address from a utxo
        let address = utxos[0]
            .address
            .clone()
            .context("Missing address")?
            .require_network(network)
            .context("Invalid network for address")?;

        match da_data {
            DaData::ZKProof(zkproof) => {
                let data = split_proof(zkproof);

                let reveal_light_client_prefix = self.to_light_client_prefix.clone();
                // create inscribe transactions
                let inscription_txs = tokio::task::spawn_blocking(move || {
                    // Since this is CPU bound work, we use spawn_blocking
                    // to release the tokio runtime execution
                    create_zkproof_transactions(
                        data,
                        da_private_key,
                        prev_utxo,
                        utxos,
                        address,
                        fee_sat_per_vbyte,
                        fee_sat_per_vbyte,
                        network,
                        reveal_light_client_prefix,
                    )
                })
                .await??;

                // write txs to file, it can be used to continue revealing blob if something goes wrong
                inscription_txs.write_to_file(self.tx_backup_dir.clone())?;

                match inscription_txs {
                    LightClientTxs::Complete { commit, reveal } => {
                        self.send_complete_transaction(commit, reveal).await
                    }
                    LightClientTxs::Chunked {
                        commit_chunks,
                        reveal_chunks,
                        commit,
                        reveal,
                    } => {
                        self.send_chunked_transaction(commit_chunks, reveal_chunks, commit, reveal)
                            .await
                    }
                }
            }
            DaData::SequencerCommitment(comm) => {
                let data = DaDataBatchProof::SequencerCommitment(comm);
                let blob = borsh::to_vec(&data).expect("DaDataBatchProof serialize must not fail");

                let prefix = self.to_batch_proof_prefix.clone();
                // create inscribe transactions
                let inscription_txs = tokio::task::spawn_blocking(move || {
                    // Since this is CPU bound work, we use spawn_blocking
                    // to release the tokio runtime execution
                    create_seqcommitment_transactions(
                        blob,
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
                .await??;

                // write txs to file, it can be used to continue revealing blob if something goes wrong
                inscription_txs.write_to_file(self.tx_backup_dir.clone())?;

                let BatchProvingTxs { commit, reveal } = inscription_txs;

                self.send_complete_transaction(commit, reveal).await
            }
        }
    }

    pub async fn send_chunked_transaction(
        &self,
        commit_chunks: Vec<Transaction>,
        reveal_chunks: Vec<Transaction>,
        commit: Transaction,
        reveal: TxWithId,
    ) -> Result<(Vec<Txid>, TxWithId)> {
        debug!("Sending chunked transaction");
        let mut raw_txs = Vec::with_capacity(commit_chunks.len() * 2 + 2);

        for (commit, reveal) in commit_chunks.into_iter().zip(reveal_chunks) {
            let signed_raw_commit_tx = self
                .client
                .sign_raw_transaction_with_wallet(&commit, None, None)
                .await?;
            raw_txs.push(signed_raw_commit_tx.hex);
            let serialized_reveal_tx = encode::serialize(&reveal);
            raw_txs.push(serialized_reveal_tx);
        }

        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;
        raw_txs.push(signed_raw_commit_tx.hex);

        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        raw_txs.push(serialized_reveal_tx);

        self.test_mempool_accept(&raw_txs).await?;
        let txids = self.send_raw_transactions(&raw_txs).await?;

        for txid in txids[1..txids.len() - 1].iter().step_by(2) {
            info!("Blob chunk inscribe tx sent. Hash: {txid}");
        }

        if let Some(last_txid) = txids.last() {
            info!("Blob chunk aggregate tx sent. Hash: {last_txid}");
        }

        Ok((txids, reveal))
    }

    pub async fn send_complete_transaction(
        &self,
        commit: Transaction,
        reveal: TxWithId,
    ) -> Result<(Vec<Txid>, TxWithId)> {
        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;
        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        let raw_txs = [signed_raw_commit_tx.hex, serialized_reveal_tx];

        self.test_mempool_accept(&raw_txs).await?;

        let txids = self.send_raw_transactions(&raw_txs).await?;
        info!("Blob inscribe tx sent. Hash: {}", txids[1]);
        Ok((txids, reveal))
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn test_mempool_accept(&self, raw_txs: &[Vec<u8>]) -> Result<()> {
        let results = self
            .client
            .test_mempool_accept(
                raw_txs
                    .iter()
                    .map(|tx| tx.as_slice())
                    .collect::<Vec<&[u8]>>()
                    .as_slice(),
            )
            .await?;

        for res in results {
            if let TestMempoolAcceptResult {
                allowed: Some(false) | None,
                reject_reason,
                ..
            } = res
            {
                bail!(
                    "{}",
                    reject_reason.unwrap_or("[testmempoolaccept] Unkown rejection".to_string())
                )
            }
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn send_raw_transactions(&self, raw_txs: &[Vec<u8>]) -> Result<Vec<Txid>> {
        let mut txids = Vec::with_capacity(raw_txs.len());
        for tx in raw_txs {
            let txid = self.client.send_raw_transaction(tx.as_slice()).await?;
            txids.push(txid);
        }
        Ok(txids)
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate(&self) -> Result<u64> {
        match self.get_fee_rate_as_sat_vb().await {
            Ok(fee) => Ok(fee),
            Err(e) => {
                if self.network == bitcoin::Network::Regtest
                    || self.network == bitcoin::Network::Testnet
                {
                    Ok(1)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate_as_sat_vb(&self) -> Result<u64> {
        // If network is regtest or signet, mempool space is not available
        let smart_fee = match get_fee_rate_from_mempool_space(self.network).await {
            Ok(fee_rate) => fee_rate,
            Err(e) => {
                tracing::error!(?e, "Failed to get fee rate from mempool.space");
                self.client.estimate_smart_fee(1, None).await?.fee_rate
            }
        };
        let sat_vkb = smart_fee.map_or(1000, |rate| rate.to_sat());

        tracing::debug!("Fee rate: {} sat/vb", sat_vkb / 1000);
        Ok(sat_vkb / 1000)
    }

    /// Bump TX fee via cpfp.
    /// If txid is None, resolves to the latest TX in chain
    pub async fn bump_fee_cpfp(&self, txid: Option<Txid>, fee_rate: f64) -> Result<Txid> {
        // Look for input tx or resolve to monitored last_tx
        let parent_txid = match txid {
            None => {
                self.monitoring
                    .get_last_tx()
                    .await
                    .context("No monitored tx")?
                    .0
            }
            Some(txid) => txid,
        };

        let monitored_tx = self
            .monitoring
            .get_monitored_tx(&parent_txid)
            .await
            .context("Parent tx not found")?;

        let TxStatus::Pending {
            base_fee: parent_fee,
            ..
        } = monitored_tx.status
        else {
            bail!(
                "Cannot bump fee for TX with status: {:?}. Transaction must be in mempool",
                monitored_tx.status
            )
        };
        debug!("Creating cpfp TX for {parent_txid}");

        let parent_tx = &monitored_tx.tx;
        let output_index = 0;
        let output_value = parent_tx.output[output_index].value;

        let create_tx_input = |outpoint: OutPoint| TxIn {
            previous_output: outpoint,
            script_sig: script::Builder::new().into_script(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut child_tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![create_tx_input(OutPoint {
                txid: parent_txid,
                vout: output_index as u32,
            })],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: parent_tx.output[output_index].script_pubkey.clone(),
            }],
        };

        let parent_vsize = parent_tx.vsize() as f64;
        let calculate_child_fee = |tx: &Transaction| -> Amount {
            let child_vsize = tx.vsize() as f64;
            let total_vsize = parent_vsize + child_vsize;
            let total_required_fee = (fee_rate * total_vsize).ceil() as u64;
            Amount::from_sat(total_required_fee.saturating_sub(parent_fee))
        };

        let mut required_fee = calculate_child_fee(&child_tx);
        let mut total_input = output_value;
        if total_input <= required_fee {
            let unspent = self
                .client
                .list_unspent(None, None, None, None, None)
                .await?;

            for utxo in unspent {
                child_tx.input.push(create_tx_input(OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                }));

                total_input += utxo.amount;
                required_fee = calculate_child_fee(&child_tx);

                if total_input > required_fee + output_value {
                    break;
                }
            }

            if total_input <= required_fee {
                bail!("Insufficient funds to cover fee bump");
            }
        }

        child_tx.output[0].value = total_input - required_fee;

        let signed_tx = self
            .client
            .sign_raw_transaction_with_wallet(&child_tx, None, None)
            .await?;

        if let Err(e) = self.client.test_mempool_accept(&[&signed_tx.hex]).await {
            bail!("Tx not accepted in mempool : {e}");
        }

        let child_txid = self.client.send_raw_transaction(&signed_tx.hex).await?;

        self.monitoring
            .monitor_transaction(child_txid, Some(parent_txid), None)
            .await?;
        self.monitoring.set_next_tx(&parent_txid, child_txid).await;

        Ok(child_txid)
    }
}

#[async_trait]
impl DaService for BitcoinService {
    type Spec = BitcoinSpec;

    type Verifier = BitcoinVerifier;

    type FilteredBlock = BitcoinBlock;

    type HeaderStream = BitcoinHeaderStream;

    type TransactionId = TxidWrapper;

    type Error = anyhow::Error;

    type BlockHash = bitcoin::BlockHash;

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
                                bail!(rpc_err.message);
                            }
                        }
                        _ => bail!(e),
                    }
                }
            };

            break;
        }

        let block = self.get_block_by_hash(block_hash).await?;

        Ok(block)
    }

    // Fetch the [`DaSpec::BlockHeader`] of the last finalized block.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_last_finalized_block_header(&self) -> Result<<Self::Spec as DaSpec>::BlockHeader> {
        let block_count = self.client.get_block_count().await?;

        let finalized_blockhash = self
            .client
            .get_block_hash(block_count.saturating_sub(FINALITY_DEPTH).saturating_add(1))
            .await?;

        let finalized_block_header = self.get_block_by_hash(finalized_blockhash).await?;

        Ok(finalized_block_header.header)
    }

    // Fetch the head block of DA.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_head_block_header(&self) -> Result<<Self::Spec as DaSpec>::BlockHeader> {
        let best_blockhash = self.client.get_best_block_hash().await?;

        let head_block_header = self.get_block_by_hash(best_blockhash).await?;

        Ok(head_block_header.header)
    }

    async fn extract_relevant_zk_proofs(
        &self,
        block: &Self::FilteredBlock,
        prover_da_pub_key: &[u8],
    ) -> Result<Vec<Proof>> {
        let mut completes = Vec::new();
        let mut aggregate_idxs = Vec::new();

        for (i, tx) in block.txdata.iter().enumerate() {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.to_light_client_prefix)
            {
                continue;
            }

            if let Ok(parsed) = parse_light_client_transaction(tx) {
                let tx_id = tx.compute_txid();
                match parsed {
                    ParsedLightClientTransaction::Complete(complete) => {
                        if complete.public_key() == prover_da_pub_key
                            && complete.get_sig_verified_hash().is_some()
                        {
                            // push only when signature is correct
                            let body = decompress_blob(&complete.body);
                            let data = DaDataLightClient::try_from_slice(&body)
                                .map_err(|e| anyhow!("{}: Failed to parse complete: {e}", tx_id))?;
                            let DaDataLightClient::Complete(zk_proof) = data else {
                                bail!("{}: Complete: unexpected kind", tx_id);
                            };
                            completes.push((i, zk_proof));
                        }
                    }
                    ParsedLightClientTransaction::Aggregate(aggregate) => {
                        if aggregate.public_key() == prover_da_pub_key
                            && aggregate.get_sig_verified_hash().is_some()
                        {
                            // push only when signature is correct
                            // collect tx ids
                            aggregate_idxs.push((i, tx_id, aggregate));
                        }
                    }
                    ParsedLightClientTransaction::Chunk(_chunk) => {
                        // we ignore them for now
                    }
                }
            }
        }

        // collect aggregated txs from chunks
        let mut aggregates = Vec::new();
        'aggregate: for (i, tx_id, aggregate) in aggregate_idxs {
            let mut body = Vec::new();
            let data = DaDataLightClient::try_from_slice(&aggregate.body)
                .map_err(|e| anyhow!("{}: Failed to parse aggregate: {e}", tx_id))?;
            let DaDataLightClient::Aggregate(chunk_ids) = data else {
                error!("{}: Aggregate: unexpected kind", tx_id);
                continue;
            };
            if chunk_ids.is_empty() {
                error!("{}: Empty aggregate tx list", tx_id);
                continue;
            }
            for chunk_id in chunk_ids {
                let chunk_id = Txid::from_byte_array(chunk_id);
                let tx_raw = {
                    let exponential_backoff = ExponentialBackoff::default();
                    let res = retry_backoff(exponential_backoff, || async move {
                        self.client
                            .get_raw_transaction(&chunk_id, None)
                            .await
                            .map_err(|e| {
                                use bitcoincore_rpc::Error;
                                match e {
                                    Error::Io(_) => backoff::Error::transient(e),
                                    _ => backoff::Error::permanent(e),
                                }
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
                let wrapped: TransactionWrapper = tx_raw.into();
                let parsed = match parse_light_client_transaction(&wrapped) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("{}:{}: Failed parse chunk: {e}", tx_id, chunk_id);
                        continue 'aggregate;
                    }
                };
                match parsed {
                    ParsedLightClientTransaction::Chunk(part) => {
                        let data = DaDataLightClient::try_from_slice(&part.body)
                            .map_err(|e| anyhow!("{}: Failed to parse chunk: {e}", tx_id))?;
                        let DaDataLightClient::Chunk(chunk) = data else {
                            bail!("{}: Chunk: unexpected kind", tx_id);
                        };
                        body.extend(chunk);
                    }
                    ParsedLightClientTransaction::Complete(_)
                    | ParsedLightClientTransaction::Aggregate(_) => {
                        error!("{}:{}: Expected chunk, got other tx kind", tx_id, chunk_id);
                        continue 'aggregate;
                    }
                }
            }
            let zk_proof: Proof = borsh::from_slice(&body)
                .map_err(|e| anyhow!("{}: Failed to parse Proof from Aggregate: {e}", tx_id))?;
            aggregates.push((i, zk_proof));
        }

        let mut proofs: Vec<_> = completes.into_iter().chain(aggregates).collect();
        // restore the order of tx they appear in the block
        proofs.sort_by_key(|b| b.0);

        let mut result = Vec::new();
        for (_i, proof) in proofs {
            result.push(proof);
        }
        Ok(result)
    }

    /// Extract SequencerCommitment's from the block
    fn extract_relevant_sequencer_commitments(
        &self,
        block: &Self::FilteredBlock,
        sequencer_da_pub_key: &[u8],
    ) -> Result<Vec<SequencerCommitment>> {
        let mut sequencer_commitments = Vec::new();

        for tx in &block.txdata {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.to_batch_proof_prefix)
            {
                continue;
            }

            if let Ok(tx) = parse_batch_proof_transaction(tx) {
                match tx {
                    ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                        if seq_comm.get_sig_verified_hash().is_some()
                            && seq_comm.public_key() == sequencer_da_pub_key
                        {
                            let data = DaDataBatchProof::try_from_slice(&seq_comm.body);
                            if let Ok(DaDataBatchProof::SequencerCommitment(seq_com)) = data {
                                sequencer_commitments.push(seq_com);
                            }
                        }
                    }
                }
            }
        }
        Ok(sequencer_commitments)
    }

    /// Extract the relevant transactions from a block, along with a proof that the extraction has been done correctly.
    /// For example, this method might return all of the blob transactions in rollup's namespace for BatchProofs/LightClient,
    /// together with a range proof against the root of the namespaced-merkle-tree, demonstrating that the entire
    /// rollup namespace has been covered.
    #[allow(clippy::type_complexity)]
    fn extract_relevant_blobs_with_proof(
        &self,
        block: &Self::FilteredBlock,
        namespace: DaNamespace,
    ) -> (
        Vec<<Self::Spec as DaSpec>::BlobTransaction>,
        <Self::Spec as DaSpec>::InclusionMultiProof,
        <Self::Spec as DaSpec>::CompletenessProof,
    ) {
        info!(
            "Getting extraction proof for block {:?}",
            block.header.block_hash()
        );

        let prefix = match namespace {
            DaNamespace::ToBatchProver => self.to_batch_proof_prefix.as_slice(),
            DaNamespace::ToLightClientProver => self.to_light_client_prefix.as_slice(),
        };

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
            match namespace {
                DaNamespace::ToBatchProver => {
                    if let Ok(tx) = parse_batch_proof_transaction(tx) {
                        match tx {
                            ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                                if let Some(hash) = seq_comm.get_sig_verified_hash() {
                                    let relevant_tx = BlobWithSender::new(
                                        seq_comm.body,
                                        seq_comm.public_key,
                                        hash,
                                    );

                                    relevant_txs.push(relevant_tx);
                                }
                            }
                        }
                    }
                }
                DaNamespace::ToLightClientProver => {
                    if let Ok(tx) = parse_light_client_transaction(tx) {
                        match tx {
                            ParsedLightClientTransaction::Complete(complete) => {
                                if let Some(hash) = complete.get_sig_verified_hash() {
                                    let blob = decompress_blob(&complete.body);
                                    let relevant_tx =
                                        BlobWithSender::new(blob, complete.public_key, hash);

                                    relevant_txs.push(relevant_tx);
                                }
                            }
                            ParsedLightClientTransaction::Aggregate(aggregate) => {
                                if let Some(hash) = aggregate.get_sig_verified_hash() {
                                    let relevant_tx = BlobWithSender::new(
                                        aggregate.body,
                                        aggregate.public_key,
                                        hash,
                                    );

                                    relevant_txs.push(relevant_tx);
                                }
                            }
                            ParsedLightClientTransaction::Chunk(_) => {
                                // ignore
                            }
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
        da_data: DaData,
    ) -> Result<<Self as DaService>::TransactionId> {
        let queue = self.get_send_transaction_queue();
        let (tx, rx) = oneshot_channel();
        queue.send(SenderWithNotifier {
            da_data,
            notify: tx,
        })?;
        rx.await?
    }

    fn get_send_transaction_queue(
        &self,
    ) -> UnboundedSender<SenderWithNotifier<Self::TransactionId>> {
        self.inscribes_queue.clone()
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_fee_rate(&self) -> Result<u128> {
        let sat_vb_ceil = self.get_fee_rate_as_sat_vb().await? as u128;

        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000 for BTC to CBTC conversion (decimals)
        let multiplied_fee = sat_vb_ceil.saturating_mul(2_500_000_000);
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(&self, hash: Self::BlockHash) -> Result<Self::FilteredBlock> {
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

        let witness_root = calculate_witness_root(&txs);

        Ok(BitcoinBlock {
            header: HeaderWrapper::new(header, txs.len() as u32, block.height, witness_root),
            txdata: txs,
        })
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
                .starts_with(&self.to_batch_proof_prefix)
            {
                continue;
            }

            if let Ok(tx) = parse_batch_proof_transaction(tx) {
                match tx {
                    ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                        // we check on da pending txs of our wallet however let's keep consistency
                        if seq_comm.get_sig_verified_hash().is_some()
                            && seq_comm.public_key == sequencer_da_pub_key
                        {
                            let da_data = DaDataBatchProof::try_from_slice(&seq_comm.body);
                            match da_data {
                                Ok(da_data) => match da_data {
                                    DaDataBatchProof::SequencerCommitment(commitment) => {
                                        sequencer_commitments.push(commitment);
                                    }
                                },
                                Err(err) => {
                                    warn!("Pending transaction blob failed to be parsed: {}", err);
                                }
                            }
                        }
                    }
                }
            }
        }
        sequencer_commitments
    }
}

pub fn get_relevant_blobs_from_txs(
    txs: Vec<Transaction>,
    reveal_wtxid_prefix: &[u8],
) -> Vec<BlobWithSender> {
    let mut relevant_txs = Vec::new();

    for tx in txs {
        if !tx
            .compute_wtxid()
            .to_byte_array()
            .as_slice()
            .starts_with(reveal_wtxid_prefix)
        {
            continue;
        }

        if let Ok(tx) = parse_batch_proof_transaction(&tx) {
            match tx {
                ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                    if let Some(hash) = seq_comm.get_sig_verified_hash() {
                        let relevant_tx =
                            BlobWithSender::new(seq_comm.body, seq_comm.public_key, hash);

                        relevant_txs.push(relevant_tx);
                    }
                }
            }
        }
    }
    relevant_txs
}

#[derive(PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxidWrapper(Txid);
impl From<TxidWrapper> for [u8; 32] {
    fn from(val: TxidWrapper) -> Self {
        val.0.to_byte_array()
    }
}

/// This function splits Proof based on its size. It is either:
/// 1: compress(borsh(DaDataLightClient::Complete(Proof)))
/// 2:
///   let compressed = compress(borsh(Proof))
///   let chunks = compressed.chunks(MAX_TXBODY_SIZE)
///   [borsh(DaDataLightClient::Chunk(chunk)) for chunk in chunks]
fn split_proof(zk_proof: Proof) -> RawLightClientData {
    let original_blob = borsh::to_vec(&zk_proof).expect("zk::Proof serialize must not fail");
    let original_compressed = compress_blob(&original_blob);
    if original_compressed.len() < MAX_TXBODY_SIZE {
        let data = DaDataLightClient::Complete(zk_proof);
        let blob = borsh::to_vec(&data).expect("zk::Proof serialize must not fail");
        let blob = compress_blob(&blob);
        RawLightClientData::Complete(blob)
    } else {
        let mut chunks = vec![];
        for chunk in original_compressed.chunks(MAX_TXBODY_SIZE) {
            let data = DaDataLightClient::Chunk(chunk.to_vec());
            let blob = borsh::to_vec(&data).expect("zk::Proof Chunk serialize must not fail");
            chunks.push(blob)
        }
        RawLightClientData::Chunks(chunks)
    }
}

fn calculate_witness_root(txdata: &[TransactionWrapper]) -> [u8; 32] {
    let hashes = txdata
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash().to_byte_array()
            } else {
                t.compute_wtxid().to_raw_hash().to_byte_array()
            }
        })
        .collect();
    BitcoinMerkleTree::new(hashes).root()
}

pub(crate) async fn get_fee_rate_from_mempool_space(
    network: bitcoin::Network,
) -> Result<Option<Amount>> {
    let url = match network {
        bitcoin::Network::Bitcoin => format!(
            // Mainnet
            "{}{}",
            MEMPOOL_SPACE_URL, MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT
        ),
        bitcoin::Network::Testnet => format!(
            "{}testnet4/{}",
            MEMPOOL_SPACE_URL, MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT
        ),
        _ => {
            trace!("Unsupported network for mempool space fee estimation");
            return Ok(None);
        }
    };
    let fee_rate = reqwest::get(url)
        .await?
        .json::<serde_json::Value>()
        .await?
        .get("fastestFee")
        .and_then(|fee| fee.as_u64())
        .map(|fee| Amount::from_sat(fee * 1000)) // multiply by 1000 to convert to sat/vkb
        .ok_or(anyhow!("Failed to get fee rate from mempool space"))?;

    Ok(Some(fee_rate))
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::path::PathBuf;
    use std::sync::Arc;

    // use futures::{Stream, StreamExt};
    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::{BlockHash, CompactTarget};
    use citrea_common::tasks::manager::TaskManager;
    use sov_rollup_interface::da::{DaNamespace, DaVerifier, SequencerCommitment};
    use sov_rollup_interface::services::da::{DaService, SlotData};

    use super::{get_fee_rate_from_mempool_space, get_relevant_blobs_from_txs, BitcoinService};
    use crate::helpers::parsers::parse_hex_transaction;
    use crate::helpers::test_utils::{get_mock_data, get_mock_txs};
    use crate::service::BitcoinServiceConfig;
    use crate::spec::block::BitcoinBlock;
    use crate::spec::header::HeaderWrapper;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::BitcoinVerifier;

    fn get_workspace_root() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir
            .ancestors()
            .nth(2)
            .expect("Failed to find workspace root")
            .to_path_buf()
    }

    fn get_tx_backup_dir() -> String {
        let mut path = get_workspace_root();
        path.push("resources/bitcoin/inscription_txs");
        path.to_str().unwrap().to_string()
    }

    async fn get_service() -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/test".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            tx_backup_dir: get_tx_backup_dir(),
            monitoring: None,
        };

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                to_batch_proof_prefix: vec![1, 1],
                to_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let da_service = Arc::new(da_service);
        // da_service.clone().spawn_da_queue(_rx);
        #[allow(clippy::let_and_return)]
        da_service
    }

    async fn get_service_wrong_namespace(
        task_manager: &mut TaskManager<()>,
    ) -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/other".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            tx_backup_dir: get_tx_backup_dir(),
            monitoring: None,
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                to_batch_proof_prefix: vec![5, 6],
                to_light_client_prefix: vec![5, 5],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let da_service = Arc::new(da_service);
        task_manager.spawn(|tk| da_service.clone().run_da_queue(rx, tk));

        da_service
    }

    async fn get_service_correct_sig_different_public_key(
        task_manager: &mut TaskManager<()>,
    ) -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/other2".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263".to_string(), // Test key, safe to publish
            ),
            tx_backup_dir: get_tx_backup_dir(),
            monitoring: None,
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                to_batch_proof_prefix: vec![1, 1],
                to_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let da_service = Arc::new(da_service);

        task_manager.spawn(|tk| da_service.clone().run_da_queue(rx, tk));

        da_service
    }

    #[tokio::test]
    #[ignore]
    /// A test we use to generate some data for the other tests
    async fn send_transaction() {
        use sov_rollup_interface::da::DaData;

        let mut task_manager = TaskManager::default();
        let da_service = get_service().await;

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [13; 32],
                l2_start_block_number: 1002,
                l2_end_block_number: 1100,
            }))
            .await
            .expect("Failed to send transaction");

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [14; 32],
                l2_start_block_number: 1101,
                l2_end_block_number: 1245,
            }))
            .await
            .expect("Failed to send transaction");

        println!("\n\nSend some BTC to this address: bcrt1qscttjdc3wypf7ttu0203sqgfz80a4q38cne693 and press enter\n\n");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();

        let size = 2000;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(blob))
            .await
            .expect("Failed to send transaction");

        println!("\n\nSend some BTC to this address: bcrt1qscttjdc3wypf7ttu0203sqgfz80a4q38cne693 and press enter\n\n");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();

        let size = 600 * 1024;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(blob))
            .await
            .expect("Failed to send transaction");

        // seq com different namespace
        get_service_wrong_namespace(&mut task_manager)
            .await
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [15; 32],
                l2_start_block_number: 1246,
                l2_end_block_number: 1268,
            }))
            .await
            .expect("Failed to send transaction");

        let size = 1024;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(blob))
            .await
            .expect("Failed to send transaction");

        // seq com incorrect pubkey and sig
        get_service_correct_sig_different_public_key(&mut task_manager)
            .await
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [15; 32],
                l2_start_block_number: 1246,
                l2_end_block_number: 1268,
            }))
            .await
            .expect("Failed to send transaction");

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [15; 32],
                l2_start_block_number: 1246,
                l2_end_block_number: 1268,
            }))
            .await
            .expect("Failed to send transaction");

        let size = 1200 * 1024;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(blob))
            .await
            .expect("Failed to send transaction");

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [30; 32],
                l2_start_block_number: 1268,
                l2_end_block_number: 1314,
            }))
            .await
            .expect("Failed to send transaction");
    }

    #[tokio::test]
    async fn extract_relevant_blobs() {
        let da_service = get_service().await;
        let (header, _inclusion_proof, _completeness_proof, relevant_txs) = get_mock_data();

        let block_txs = get_mock_txs();
        let block_txs = block_txs.into_iter().map(Into::into).collect();

        let block = BitcoinBlock {
            header,
            txdata: block_txs,
        };

        let (txs, _, _) =
            da_service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToBatchProver);

        assert_eq!(txs, relevant_txs);
    }

    #[tokio::test]
    async fn extract_relevant_blobs_with_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let da_service = get_service().await;
        let (header, _inclusion_proof, _completeness_proof, _relevant_txs) = get_mock_data();
        let block_txs = get_mock_txs();
        let block_txs = block_txs.into_iter().map(Into::into).collect();

        let block = BitcoinBlock {
            header,
            txdata: block_txs,
        };

        let (txs, inclusion_proof, completeness_proof) =
            da_service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToBatchProver);

        assert!(verifier
            .verify_transactions(
                block.header(),
                &txs,
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver
            )
            .is_ok());
    }

    #[tokio::test]
    async fn incorrect_private_key_signature_should_fail() {
        // The transaction was sent with this service and the tx data is stored in false_signature_txs.txt
        let da_service = get_service().await;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let da_pubkey = Keypair::from_secret_key(&secp, &da_service.da_private_key.unwrap())
            .public_key()
            .serialize()
            .to_vec();

        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33261".to_string(), // Test key, safe to publish
            ),
            tx_backup_dir: get_tx_backup_dir(),
            monitoring: None,
        };

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let incorrect_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                to_batch_proof_prefix: vec![1, 1],
                to_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let incorrect_pub_key =
            Keypair::from_secret_key(&secp, &incorrect_service.da_private_key.unwrap())
                .public_key()
                .serialize()
                .to_vec();

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "31402555f54c3f89907c07e6d286c132f9984739f2b6b00cde195b10ac771522",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "40642938a6cc6124246fd9601108f9671177c1834753162f19e073eaff751191",
                )
                .unwrap(),
                time: 1724665818,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 3,
            },
            3,
            1,
            WitnessMerkleNode::from_str(
                "494880ce756f69b13811200d1e358a049ac3c3dd66e4ff7e86d4c4d3aad95939",
            )
            .unwrap()
            .as_raw_hash()
            .to_byte_array(),
        );

        let txs_str = std::fs::read_to_string("test_data/false_signature_txs.txt").unwrap();

        let txdata: Vec<TransactionWrapper> = txs_str
            .lines()
            .map(|tx| parse_hex_transaction(tx).unwrap())
            .map(Into::into)
            .collect();

        let block = BitcoinBlock { header, txdata };

        let (txs, _, _) =
            da_service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToBatchProver);

        assert_ne!(
            txs.first().unwrap().sender.0,
            da_pubkey,
            "Publickey recovered incorrectly!"
        );

        assert_eq!(
            txs.first().unwrap().sender.0,
            incorrect_pub_key,
            "Publickey recovered incorrectly!"
        );
    }

    #[tokio::test]
    async fn check_signature() {
        let da_service = get_service().await;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let da_pubkey = Keypair::from_secret_key(&secp, &da_service.da_private_key.unwrap())
            .public_key()
            .serialize()
            .to_vec();

        // blob written in tx is: "01000000b60000002adbd76606f2bd4125080e6f44df7ba2d728409955c80b8438eb1828ddf23e3c12188eeac7ecf6323be0ed5668e21cc354fca90d8bca513d6c0a240c26afa7007b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe64a0000000001fea6ac5b8751120fb62fff67b54d2eac66aef307c7dde1d394dea1e09e43dd44c800000000000000135d23aee8cb15c890831ff36db170157acaac31df9bba6cd40e7329e608eabd0000000000000000";
        // tx id = 0x8a1df48198a509cd91930ff44cbb92ef46e80458b1999e16aa6923171894fba3
        // block hash = 0x4ebbe86ead2e7f397419c25b0757bea281353a0592eb692614d13f0e87c5a7ff
        // the tx_hex = "020000000001012a2b5f4a9aef27067aff1bfe058076043667f0618075b94253d58c9f5b7b85d40000000000fdffffff01220200000000000016001421e826b290c95a5c65059b3a48e97a91f422d1330340f1148ce0807ebd683fad97376225ea2eea0dcef89f609e6e563bc5bb4f25c34d96e4741da9d84130ddb9b5a111703332983fdd20a461ae25c9434cde1e9d8733fd60012044e67148e60dd2ab07bb2505f2e3e9298aada763dd4635bce71bcf2f96a6691aac0063010107736f762d627463010240cc4b23d2cb3e22b2c57a59f24088764f39f7b789847e983b9ee9ce7682578c2b7dbdf4384e230c942b91ae5ce6b1ba33587f549fedee4d19e54ff3a8e54601e801032102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9010400004cc41b7b01f845c786b10e90638b5cd88023081823b06c20b90040401052860738a7c6cd60c7358f581158bbf7e6bc92c7391efe57ed40c593d8a2e09839969526a688dd6cdf3e13965aeca8592c53b7e8bbce8f89ea5492b146f243b3e5a5035eae51c7ebe6b8bc3cab03487b71a7990116d8b5afdc53370e95bb16a7c0adbd8489749b96ad15ae448c2be3bb332f7dc39b6d967b026f9f591af96f3669f1f7c9cc7b1dd047a2c392bbd145daf11142776253e420f5eccc169afb55693d0febc27f0db159036821c044e67148e60dd2ab07bb2505f2e3e9298aada763dd4635bce71bcf2f96a6691a00000000";
        // let header = HeaderWrapper::new(
        //     Header {
        //         version: Version::from_consensus(536870912),
        //         prev_blockhash: BlockHash::from_str(
        //             "4ebd11342b9d9e2a23b0f14c17a12bbb4f52a9290fe6a1cf313c270d5a49c2ea",
        //         )
        //         .unwrap(),
        //         merkle_root: TxMerkleNode::from_str(
        //             "a720804fbad45307b61958059c06f787a1ae10180ce91df2802a40023dea7e84",
        //         )
        //         .unwrap(),
        //         time: 1723820296,
        //         bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
        //         nonce: 0,
        //     },
        //     3,
        //     2273,
        //     WitnessMerkleNode::from_str(
        //         "ab0edbf1611637701117cfc70b878b4196be1c5e4c256609ca8b620a0838860a",
        //     )
        //     .unwrap()
        //     .as_raw_hash()
        //     .to_byte_array(),
        // );

        let txs_str = std::fs::read_to_string("test_data/mock_txs.txt").unwrap();

        let txdata: Vec<_> = txs_str
            .lines()
            .map(|tx| parse_hex_transaction(tx).unwrap())
            .collect();

        let txs = get_relevant_blobs_from_txs(txdata, &[1]);

        assert_eq!(
            txs.first().unwrap().sender.0,
            da_pubkey,
            "Publickey recovered incorrectly!"
        );
    }

    #[tokio::test]
    async fn test_mempool_space_fee_rate() {
        let _fee_rate = get_fee_rate_from_mempool_space(bitcoin::Network::Bitcoin)
            .await
            .unwrap();
        let _fee_rate = get_fee_rate_from_mempool_space(bitcoin::Network::Testnet)
            .await
            .unwrap();
        assert_eq!(
            None,
            get_fee_rate_from_mempool_space(bitcoin::Network::Regtest)
                .await
                .unwrap()
        );
        assert_eq!(
            None,
            get_fee_rate_from_mempool_space(bitcoin::Network::Signet)
                .await
                .unwrap()
        );
    }
}
