// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use bitcoin::block::Header;
use bitcoin::consensus::{encode, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, CompactTarget, Transaction, Txid, Wtxid};
use bitcoincore_rpc::json::{SignRawTransactionInput, TestMempoolAcceptResult};
use bitcoincore_rpc::{Auth, Client, Error as BitcoinError, Error, RpcApi, RpcError};
use borsh::BorshDeserialize;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::MAX_TXBODY_SIZE;
use metrics::histogram;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaSpec, DaTxRequest, DataOnDa, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use sov_rollup_interface::zk::Proof;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::fee::{BumpFeeMethod, FeeService};
use crate::helpers::builders::body_builders::{create_light_client_transactions, DaTxs, RawTxData};
use crate::helpers::builders::{TxListWithReveal, TxWithId};
use crate::helpers::merkle_tree;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use crate::monitoring::{MonitoredTxKind, MonitoringConfig, MonitoringService, TxStatus};
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::header_stream::BitcoinHeaderStream;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::short_proof::BitcoinHeaderShortProof;
use crate::spec::transaction::TransactionWrapper;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::verifier::BitcoinVerifier;
use crate::REVEAL_OUTPUT_AMOUNT;

#[cfg(feature = "testing")]
pub const FINALITY_DEPTH: u64 = 5; // blocks
#[cfg(not(feature = "testing"))]
pub const FINALITY_DEPTH: u64 = 100; // blocks
const POLLING_INTERVAL: u64 = 10; // seconds

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
    pub mempool_space_url: Option<String>,
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
            monitoring: MonitoringConfig::from_env().ok(),
            mempool_space_url: std::env::var("MEMPOOL_SPACE_URL").ok(),
        })
    }
}

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug)]
pub struct BitcoinService {
    client: Arc<Client>,
    network: bitcoin::Network,
    da_private_key: Option<SecretKey>,
    reveal_tx_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
    tx_backup_dir: PathBuf,
    pub monitoring: Arc<MonitoringService>,
    fee: FeeService,
}

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub async fn new_with_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
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
        let fee = FeeService::new(client.clone(), config.network, config.mempool_space_url);
        Ok(Self {
            client,
            network: config.network,
            da_private_key: private_key,
            reveal_tx_prefix: chain_params.reveal_tx_prefix,
            inscribes_queue: tx,
            tx_backup_dir: tx_backup_dir.to_path_buf(),
            monitoring,
            fee,
        })
    }

    pub async fn new_without_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<TxRequestWithNotifier<TxidWrapper>>,
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
        let fee = FeeService::new(client.clone(), config.network, config.mempool_space_url);

        Ok(Self {
            client,
            network: config.network,
            da_private_key,
            reveal_tx_prefix: chain_params.reveal_tx_prefix,
            inscribes_queue: tx,
            tx_backup_dir: tx_backup_dir.to_path_buf(),
            monitoring,
            fee,
        })
    }

    pub async fn run_da_queue(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<TxRequestWithNotifier<TxidWrapper>>,
        token: CancellationToken,
    ) {
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
                        loop {
                            // Build and send tx with retries:
                            let fee_sat_per_vbyte = match self.fee.get_fee_rate().await {
                                Ok(rate) => rate,
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
                            Ok(txids) => {
                                let txid = txids.last().unwrap();
                                let tx_id = TxidWrapper(*txid);
                                info!(%txid, "Sent tx to BitcoinDA");
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
    #[instrument(level = "trace", skip_all, ret)]
    async fn get_prev_utxo(&self) -> Option<UTXO> {
        let (txid, tx) = self.monitoring.get_last_tx().await?;

        let utxos = tx.to_utxos()?;

        // Check that tx out is still spendable
        // If not found, utxo is already spent
        self.client.get_tx_out(&txid, 0, Some(true)).await.ok()??;

        // Return first vout
        utxos.into_iter().next()
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
            .get_monitored_txs()
            .await
            .into_iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::Pending { .. }))
            .map(|(_, monitored_tx)| monitored_tx.tx)
            .collect()
    }

    #[instrument(level = "trace", fields(prev_utxo), ret, err)]
    pub async fn send_transaction_with_fee_rate(
        &self,
        tx_request: DaTxRequest,
        fee_sat_per_vbyte: u64,
    ) -> Result<Vec<Txid>> {
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
            .require_network(network)
            .context("Invalid network for address")?;

        match tx_request {
            DaTxRequest::ZKProof(zkproof) => {
                let data = split_proof(zkproof)?;

                let reveal_light_client_prefix = self.reveal_tx_prefix.clone();
                // create inscribe transactions
                let inscription_txs = tokio::task::spawn_blocking(move || {
                    // Since this is CPU bound work, we use spawn_blocking
                    // to release the tokio runtime execution
                    create_light_client_transactions(
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

                match inscription_txs.clone() {
                    DaTxs::Complete { commit, reveal } => {
                        self.send_complete_transaction(
                            commit,
                            reveal,
                            inscription_txs,
                            self.tx_backup_dir.clone(),
                        )
                        .await
                    }
                    DaTxs::Chunked {
                        commit_chunks,
                        reveal_chunks,
                        commit,
                        reveal,
                    } => {
                        self.send_chunked_transaction(
                            commit_chunks,
                            reveal_chunks,
                            commit,
                            reveal,
                            inscription_txs,
                            self.tx_backup_dir.clone(),
                        )
                        .await
                    }
                    _ => panic!("ZKProof tx must be either complete or chunked"),
                }
            }
            DaTxRequest::SequencerCommitment(comm) => {
                let data = DataOnDa::SequencerCommitment(comm);
                let blob = borsh::to_vec(&data).expect("DataOnDa serialize must not fail");

                let prefix = self.reveal_tx_prefix.clone();
                // create inscribe transactions
                let inscription_txs = tokio::task::spawn_blocking(move || {
                    // Since this is CPU bound work, we use spawn_blocking
                    // to release the tokio runtime execution
                    create_light_client_transactions(
                        RawTxData::SequencerCommitment(blob),
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

                match inscription_txs.clone() {
                    DaTxs::SequencerCommitment { commit, reveal } => {
                        self.send_complete_transaction(
                            commit,
                            reveal,
                            inscription_txs,
                            self.tx_backup_dir.clone(),
                        )
                        .await
                    }
                    _ => panic!("Tx must be SequencerCommitment"),
                }
            }
            DaTxRequest::BatchProofMethodId(method_id) => {
                let data = DataOnDa::BatchProofMethodId(method_id);
                let blob = borsh::to_vec(&data).expect("DataOnDa serialize must not fail");

                let prefix = self.reveal_tx_prefix.clone();

                // create inscribe transactions
                let inscription_txs = tokio::task::spawn_blocking(move || {
                    // Since this is CPU bound work, we use spawn_blocking
                    // to release the tokio runtime execution
                    create_light_client_transactions(
                        RawTxData::BatchProofMethodId(blob),
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

                match inscription_txs.clone() {
                    DaTxs::BatchProofMethodId { commit, reveal } => {
                        self.send_complete_transaction(
                            commit,
                            reveal,
                            inscription_txs,
                            self.tx_backup_dir.clone(),
                        )
                        .await
                    }
                    _ => panic!("Tx must be BatchProofMethodId"),
                }
            }
        }
    }

    async fn send_chunked_transaction(
        &self,
        commit_chunks: Vec<Transaction>,
        reveal_chunks: Vec<Transaction>,
        commit: Transaction,
        reveal: TxWithId,
        back_up_txs: DaTxs,
        back_up_path: PathBuf,
    ) -> Result<Vec<Txid>> {
        assert!(!commit_chunks.is_empty(), "Received empty chunks");
        assert_eq!(
            commit_chunks.len(),
            reveal_chunks.len(),
            "Chunks commit and reveal length mismatch"
        );

        debug!("Sending chunked transaction");

        let all_tx_map = commit_chunks
            .iter()
            .chain(reveal_chunks.iter())
            .chain([&commit, &reveal.tx].into_iter())
            .map(|tx| (tx.compute_txid(), tx.clone()))
            .collect::<HashMap<_, _>>();

        let mut raw_txs = Vec::with_capacity(all_tx_map.len());

        for (commit, reveal) in commit_chunks.into_iter().zip(reveal_chunks) {
            let mut inputs = vec![];

            for input in commit.input.iter() {
                if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                    inputs.push(SignRawTransactionInput {
                        txid: input.previous_output.txid,
                        vout: input.previous_output.vout,
                        script_pub_key: entry.output[input.previous_output.vout as usize]
                            .script_pubkey
                            .clone(),
                        redeem_script: None,
                        amount: Some(entry.output[input.previous_output.vout as usize].value),
                    });
                }
            }

            let signed_raw_commit_tx = self
                .client
                .sign_raw_transaction_with_wallet(&commit, Some(inputs.as_slice()), None)
                .await?;

            if let Some(errors) = signed_raw_commit_tx.errors {
                bail!("Failed to sign commit transaction: {:?}", errors);
            }

            raw_txs.push(signed_raw_commit_tx.hex);

            let serialized_reveal_tx = encode::serialize(&reveal);
            raw_txs.push(serialized_reveal_tx);
        }

        let mut inputs = vec![];

        for input in commit.input.iter() {
            if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                inputs.push(SignRawTransactionInput {
                    txid: input.previous_output.txid,
                    vout: input.previous_output.vout,
                    script_pub_key: entry.output[input.previous_output.vout as usize]
                        .script_pubkey
                        .clone(),
                    redeem_script: None,
                    amount: Some(entry.output[input.previous_output.vout as usize].value),
                });
            }
        }
        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, Some(inputs.as_slice()), None)
            .await?;

        if let Some(errors) = signed_raw_commit_tx.errors {
            bail!(
                "Failed to sign the aggregate commit transaction: {:?}",
                errors
            );
        }

        raw_txs.push(signed_raw_commit_tx.hex);

        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        raw_txs.push(serialized_reveal_tx);

        self.test_mempool_accept(&raw_txs).await?;

        // backup tx only if it passes mempool accept test
        back_up_txs.write_to_file(back_up_path)?;

        // Track the sum of all chunked transactions sizes
        let raw_txs_size_sum: usize = raw_txs.iter().map(|tx| tx.len()).sum();
        histogram!("da_transaction_size").record(raw_txs_size_sum as f64);

        let txids = self.send_raw_transactions(&raw_txs).await?;

        for txid in txids[1..].iter().step_by(2) {
            info!("Blob chunk inscribe tx sent. Hash: {txid}");
        }

        if let Some(last_txid) = txids.last() {
            info!("Blob chunk aggregate tx sent. Hash: {last_txid}");
        }

        Ok(txids)
    }

    async fn send_complete_transaction(
        &self,
        commit: Transaction,
        reveal: TxWithId,
        back_up_txs: DaTxs,
        back_up_path: PathBuf,
    ) -> Result<Vec<Txid>> {
        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;

        if let Some(errors) = signed_raw_commit_tx.errors {
            bail!("Failed to sign commit transaction: {:?}", errors);
        }

        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        let raw_txs = [signed_raw_commit_tx.hex, serialized_reveal_tx];

        // Track the sum of both commit and reveal transaction sizes
        let raw_txs_size_sum: usize = raw_txs.iter().map(|tx| tx.len()).sum();
        histogram!("da_transaction_size").record(raw_txs_size_sum as f64);

        self.test_mempool_accept(&raw_txs).await?;

        // backup tx only if it passes mempool accept test
        back_up_txs.write_to_file(back_up_path)?;

        let txids = self.send_raw_transactions(&raw_txs).await?;
        info!("Blob inscribe tx sent. Hash: {}", txids[1]);
        Ok(txids)
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
                    reject_reason.unwrap_or("[testmempoolaccept] Unknown rejection".to_string())
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

        let TxStatus::Pending { .. } = tx.status else {
            bail!(
                "Cannot bump fee for TX with status: {:?}. Transaction must be pending",
                tx.status
            )
        };

        let Some(utxo) = self.get_prev_utxo().await else {
            bail!("Cannot bump fee without prev_utxo available")
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

        let Some(raw_hex) = processed.hex else {
            bail!("Couldn't finalize psbt")
        };

        if let Err(e) = self.client.test_mempool_accept(&[&raw_hex]).await {
            bail!("Tx not accepted in mempool : {e}");
        }

        let new_txid = self.client.send_raw_transaction(&raw_hex).await?;
        histogram!("da_transaction_size").record(raw_hex.len() as f64);

        match method {
            BumpFeeMethod::Cpfp => {
                self.monitoring
                    .monitor_transaction(new_txid, Some(txid), None, MonitoredTxKind::Cpfp)
                    .await?;
                self.monitoring.set_next_tx(&txid, new_txid).await;
            }
            BumpFeeMethod::Rbf => self.monitoring.replace_txid(txid, new_txid).await?,
        };

        Ok(new_txid)
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
        let block = self.get_block_by_hash(block_hash.into()).await?;

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

    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>, Self::Error> {
        BitcoinSpec::decompress_chunks(complete_chunks)
            .map_err(|_| anyhow!("Failed to parse complete chunks"))
    }

    async fn extract_relevant_zk_proofs(
        &self,
        block: &Self::FilteredBlock,
        prover_da_pub_key: &[u8],
    ) -> Vec<Proof> {
        let mut completes = Vec::new();
        let mut aggregate_idxs = Vec::new();

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
                            // push only when signature is correct
                            let Ok(body) = decompress_blob(&complete.body) else {
                                warn!("{tx_id}: Failed to decompress blob");
                                continue;
                            };

                            let Ok(data) = DataOnDa::borsh_parse_complete(&body) else {
                                warn!("{tx_id}: Failed to parse complete data");
                                continue;
                            };

                            let DataOnDa::Complete(zk_proof) = data else {
                                warn!("{}: Complete: unexpected kind", tx_id);
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
                        // we ignore them for now
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
        'aggregate: for (i, tx_id, aggregate) in aggregate_idxs {
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
                let tx_raw = {
                    let exponential_backoff = ExponentialBackoff::default();
                    let res = retry_backoff(exponential_backoff, || async move {
                        self.client
                            .get_raw_transaction(&chunk_id, None)
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

                let wrapped: TransactionWrapper = tx_raw.into();
                let parsed = match parse_relevant_transaction(&wrapped) {
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
            let Ok(blob) = decompress_blob(&body) else {
                warn!("{tx_id}: Failed to decompress blob from Aggregate");
                continue 'aggregate;
            };
            let Ok(zk_proof) = borsh::from_slice(blob.as_slice()) else {
                warn!("{}: Failed to parse Proof from Aggregate", tx_id);
                continue 'aggregate;
            };
            aggregates.push((i, zk_proof));
        }

        let mut proofs: Vec<_> = completes.into_iter().chain(aggregates).collect();
        // restore the order of tx they appear in the block
        proofs.sort_by_key(|b| b.0);

        proofs.into_iter().map(|(_, proof)| proof).collect()
    }

    /// Extract SequencerCommitment's from the block
    fn extract_relevant_sequencer_commitments(
        &self,
        block: &Self::FilteredBlock,
        sequencer_da_pub_key: &[u8],
    ) -> Vec<SequencerCommitment> {
        let mut sequencer_commitments = Vec::new();

        for tx in &block.txdata {
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
                        sequencer_commitments.push(seq_com);
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
                            let Ok(blob) = decompress_blob(&complete.body) else {
                                continue;
                            };
                            let relevant_tx = BlobWithSender::new(
                                blob,
                                complete.public_key,
                                hash,
                                Some(wtxid.to_byte_array()),
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
                                Some(wtxid.to_byte_array()),
                            );
                            relevant_txs.push(relevant_tx);
                        }
                    }
                    ParsedTransaction::Chunk(chunk) => {
                        let relevant_tx = BlobWithSender::new(
                            chunk.body,
                            vec![],
                            [0; 32],
                            Some(wtxid.to_byte_array()),
                        );
                        relevant_txs.push(relevant_tx);
                    }
                    ParsedTransaction::BatchProverMethodId(method_id) => {
                        if let Some(hash) = method_id.get_sig_verified_hash() {
                            let relevant_tx = BlobWithSender::new(
                                method_id.body,
                                method_id.public_key,
                                hash,
                                Some(wtxid.to_byte_array()),
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
                                Some(wtxid.to_byte_array()),
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
    ) -> Result<<Self as DaService>::TransactionId> {
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
    async fn get_fee_rate(&self) -> Result<u128> {
        let sat_vb_ceil = self.fee.get_fee_rate_as_sat_vb().await? as u128;

        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000 for BTC to CBTC conversion (decimals)
        let multiplied_fee = sat_vb_ceil.saturating_mul(2_500_000_000);
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(
        &self,
        hash: <Self::Spec as DaSpec>::SlotHash,
    ) -> Result<Self::FilteredBlock> {
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

        let witness_root = calculate_witness_root(&txs);

        Ok(BitcoinBlock {
            header: HeaderWrapper::new(header, txs.len() as u32, block.height, witness_root),
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

        if let Ok(ParsedTransaction::SequencerCommitment(seq_comm)) =
            parse_relevant_transaction(&tx)
        {
            if let Some(hash) = seq_comm.get_sig_verified_hash() {
                let relevant_tx =
                    BlobWithSender::new(seq_comm.body, seq_comm.public_key, hash, None);

                relevant_txs.push(relevant_tx);
            }
        } else {
            // ignore
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
/// 1: compress(borsh(DataOnDa::Complete(Proof)))
/// 2:
///   let compressed = compress(borsh(Proof))
///   let chunks = compressed.chunks(MAX_TXBODY_SIZE)
///   [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
fn split_proof(zk_proof: Proof) -> anyhow::Result<RawTxData> {
    let original_blob = borsh::to_vec(&zk_proof).expect("zk::Proof serialize must not fail");
    let original_compressed = compress_blob(&original_blob)?;

    if original_compressed.len() < MAX_TXBODY_SIZE {
        let data = DataOnDa::Complete(zk_proof);
        let blob = borsh::to_vec(&data).expect("zk::Proof serialize must not fail");
        let blob = compress_blob(&blob)?;
        Ok(RawTxData::Complete(blob))
    } else {
        let mut chunks = vec![];
        for chunk in original_compressed.chunks(MAX_TXBODY_SIZE) {
            let data = DataOnDa::Chunk(chunk.to_vec());
            let blob = borsh::to_vec(&data).expect("zk::Proof Chunk serialize must not fail");
            chunks.push(blob)
        }

        Ok(RawTxData::Chunks(chunks))
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
