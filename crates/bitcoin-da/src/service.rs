// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
// use std::sync::Arc;
use async_trait::async_trait;
use bitcoin::block::Header;
use bitcoin::consensus::{encode, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Amount, BlockHash, CompactTarget, Transaction, Txid, Wtxid};
use bitcoincore_rpc::jsonrpc_async::Error as RpcError;
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};
use borsh::BorshDeserialize;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaData, DaDataBatchProof, DaDataLightClient, DaSpec};
use sov_rollup_interface::services::da::{DaService, SenderWithNotifier};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tracing::{debug, error, info, instrument, trace};

use crate::helpers::builders::{
    create_seqcommitment_transactions, create_zkproof_transactions, write_inscription_txs,
    BatchProvingTxs, LightClientTxs, TxWithId,
};
use crate::helpers::compression::{compress_blob, decompress_blob};
use crate::helpers::merkle_tree;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{
    parse_batch_proof_transaction, parse_light_client_transaction, ParsedBatchProofTransaction,
    ParsedLightClientTransaction, VerifyParsed,
};
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

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug)]
pub struct BitcoinService {
    client: Client,
    rollup_name: String,
    network: bitcoin::Network,
    da_private_key: Option<SecretKey>,
    reveal_light_client_prefix: Vec<u8>,
    reveal_batch_prover_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
}

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

    // number of last paid fee rates to average if estimation fails
    pub fee_rates_to_avg: Option<usize>,
}

const FINALITY_DEPTH: u64 = 4; // blocks
const POLLING_INTERVAL: u64 = 10; // seconds

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub async fn new_with_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
    ) -> Result<Self> {
        let client = Client::new(
            &config.node_url,
            Auth::UserPass(config.node_username, config.node_password),
        )
        .await?;

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

        Ok(Self {
            client,
            rollup_name: chain_params.rollup_name,
            network: config.network,
            da_private_key: private_key,
            reveal_light_client_prefix: chain_params.reveal_light_client_prefix,
            reveal_batch_prover_prefix: chain_params.reveal_batch_prover_prefix,
            inscribes_queue: tx,
        })
    }

    pub fn spawn_da_queue(
        self: Arc<Self>,
        mut rx: UnboundedReceiver<SenderWithNotifier<TxidWrapper>>,
    ) {
        // This is a queue of inscribe requests
        tokio::task::spawn_blocking(|| {
            tokio::runtime::Handle::current().block_on(async move {
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

                // We execute commit and reveal txs one by one to chain them
                while let Some(request) = rx.recv().await {
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
                            Ok(tx) => {
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

                error!("BitcoinDA queue stopped");
            });
        });
    }

    #[cfg(test)]
    pub async fn new_without_wallet_check(
        config: BitcoinServiceConfig,
        chain_params: RollupParams,
        tx: UnboundedSender<SenderWithNotifier<TxidWrapper>>,
    ) -> Result<Self> {
        let client = Client::new(
            &config.node_url,
            Auth::UserPass(config.node_username, config.node_password),
        )
        .await?;

        let da_private_key = config
            .da_private_key
            .map(|pk| SecretKey::from_str(&pk))
            .transpose()
            .context("Invalid private key")?;

        Ok(Self {
            client,
            rollup_name: chain_params.rollup_name,
            network: config.network,
            da_private_key,
            reveal_light_client_prefix: chain_params.reveal_light_client_prefix,
            reveal_batch_prover_prefix: chain_params.reveal_batch_prover_prefix,
            inscribes_queue: tx,
        })
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_prev_utxo(&self) -> Result<Option<UTXO>, anyhow::Error> {
        let mut pending_utxos = self
            .client
            .list_unspent(Some(0), Some(0), None, None, None)
            .await?;

        pending_utxos.retain(|u| u.spendable && u.solvable);

        // Sorted by ancestor count, the tx with the most ancestors is the latest tx
        pending_utxos.sort_unstable_by_key(|utxo| -(utxo.ancestor_count.unwrap_or(0) as i64));

        Ok(pending_utxos
            .into_iter()
            .find(|u| u.amount >= Amount::from_sat(REVEAL_OUTPUT_AMOUNT))
            .map(|u| u.into()))
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_utxos(&self) -> Result<Vec<UTXO>, anyhow::Error> {
        let utxos = self
            .client
            .list_unspent(None, None, None, None, None)
            .await?;
        if utxos.is_empty() {
            return Err(anyhow::anyhow!("There are no UTXOs"));
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
            return Err(anyhow::anyhow!("There are no spendable UTXOs"));
        }

        Ok(utxos)
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, anyhow::Error> {
        let mut pending_utxos = self
            .client
            .list_unspent(Some(0), Some(0), None, None, None)
            .await?;
        // Sorted by ancestor count, the tx with the most ancestors is the latest tx
        pending_utxos.sort_unstable_by_key(|utxo| -(utxo.ancestor_count.unwrap_or(0) as i64));

        let mut pending_transactions = Vec::new();
        let mut scanned_txids = HashSet::new();

        for utxo in pending_utxos.iter() {
            let txid = utxo.txid;
            // Check if tx is already in the pending transactions vector
            if scanned_txids.contains(&txid) {
                continue;
            }

            let tx = self
                .client
                .get_raw_transaction(&txid, None)
                .await
                .expect("Transaction should exist with existing utxo");
            pending_transactions.push(tx);
            scanned_txids.insert(txid);
        }

        Ok(pending_transactions)
    }

    #[instrument(level = "trace", fields(prev_utxo), ret, err)]
    pub async fn send_transaction_with_fee_rate(
        &self,
        prev_utxo: Option<UTXO>,
        da_data: DaData,
        fee_sat_per_vbyte: f64,
    ) -> Result<TxWithId, anyhow::Error> {
        let client = &self.client;
        let network = self.network;

        let rollup_name = self.rollup_name.clone();
        let da_private_key = self.da_private_key.expect("No private key set");

        // get all available utxos
        let utxos = self.get_utxos().await?;

        // get address from a utxo
        let address = utxos[0]
            .address
            .clone()
            .context("Missing address")?
            .require_network(network)
            .context("Invalid network for address")?;

        match da_data {
            DaData::ZKProof(zkproof) => {
                let data = DaDataLightClient::ZKProof(zkproof);
                let blob = borsh::to_vec(&data).expect("DaDataLightClient serialize must not fail");
                let blob = compress_blob(&blob);
                // create inscribe transactions
                let inscription_txs = create_zkproof_transactions(
                    &rollup_name,
                    blob,
                    &da_private_key,
                    prev_utxo,
                    utxos,
                    address,
                    REVEAL_OUTPUT_AMOUNT,
                    fee_sat_per_vbyte,
                    fee_sat_per_vbyte,
                    network,
                    &self.reveal_light_client_prefix,
                )?;

                // write txs to file, it can be used to continue revealing blob if something goes wrong
                write_inscription_txs(&inscription_txs);

                match inscription_txs {
                    LightClientTxs::Complete { commit, reveal } => {
                        // sign inscribe transactions
                        let signed_raw_commit_tx = client
                            .sign_raw_transaction_with_wallet(&commit, None, None)
                            .await?;

                        // send inscribe transactions
                        client
                            .send_raw_transaction(&signed_raw_commit_tx.hex)
                            .await?;

                        // serialize reveal tx
                        let serialized_reveal_tx = &encode::serialize(&reveal.tx);

                        // send reveal tx
                        let reveal_tx_hash =
                            client.send_raw_transaction(serialized_reveal_tx).await?;

                        info!("Blob inscribe tx sent. Hash: {}", reveal_tx_hash);
                        Ok(reveal)
                    }
                    LightClientTxs::Chunked {
                        commit_chunks,
                        reveal_chunks,
                        commit,
                        reveal,
                    } => {
                        for (commit, reveal) in commit_chunks.into_iter().zip(reveal_chunks) {
                            // sign inscribe transactions
                            let signed_raw_commit_tx = client
                                .sign_raw_transaction_with_wallet(&commit, None, None)
                                .await?;

                            // send inscribe transactions
                            client
                                .send_raw_transaction(&signed_raw_commit_tx.hex)
                                .await?;

                            // serialize reveal tx
                            let serialized_reveal_tx = encode::serialize(&reveal);

                            // send reveal tx
                            let reveal_tx_hash =
                                client.send_raw_transaction(&serialized_reveal_tx).await?;
                            info!("Blob chunk inscribe tx sent. Hash: {}", reveal_tx_hash);
                        }

                        // sign inscribe transactions
                        let signed_raw_commit_tx = client
                            .sign_raw_transaction_with_wallet(&commit, None, None)
                            .await?;

                        // send inscribe transactions
                        client
                            .send_raw_transaction(&signed_raw_commit_tx.hex)
                            .await?;

                        // serialize reveal tx
                        let serialized_reveal_tx = encode::serialize(&reveal.tx);

                        // send reveal tx
                        let reveal_tx_hash =
                            client.send_raw_transaction(&serialized_reveal_tx).await?;
                        info!("Blob chunk aggregate tx sent. Hash: {}", reveal_tx_hash);
                        Ok(reveal)
                    }
                }
            }
            DaData::SequencerCommitment(comm) => {
                let data = DaDataBatchProof::SequencerCommitment(comm);
                let blob = borsh::to_vec(&data).expect("DaDataBatchProof serialize must not fail");
                // create inscribe transactions
                let inscription_txs = create_seqcommitment_transactions(
                    &rollup_name,
                    blob,
                    &da_private_key,
                    prev_utxo,
                    utxos,
                    address,
                    REVEAL_OUTPUT_AMOUNT,
                    fee_sat_per_vbyte,
                    fee_sat_per_vbyte,
                    network,
                    &self.reveal_batch_prover_prefix,
                )?;

                // write txs to file, it can be used to continue revealing blob if something goes wrong
                write_inscription_txs(&inscription_txs);

                let BatchProvingTxs { commit, reveal } = inscription_txs;
                // sign inscribe transactions
                let signed_raw_commit_tx = client
                    .sign_raw_transaction_with_wallet(&commit, None, None)
                    .await?;

                // send inscribe transactions
                client
                    .send_raw_transaction(&signed_raw_commit_tx.hex)
                    .await?;

                // serialize reveal tx
                let serialized_reveal_tx = &encode::serialize(&reveal.tx);

                // send reveal tx
                let reveal_tx_hash = client.send_raw_transaction(serialized_reveal_tx).await?;

                info!("Blob inscribe tx sent. Hash: {}", reveal_tx_hash);
                Ok(reveal)
            }
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate(&self) -> Result<f64, anyhow::Error> {
        if self.network == bitcoin::Network::Regtest {
            // sometimes local mempool is empty, node cannot estimate
            return Ok(2.0);
        }

        self.get_fee_rate_as_sat_vb_ceiled().await
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate_as_sat_vb_ceiled(&self) -> Result<f64, anyhow::Error> {
        let smart_fee = self.client.estimate_smart_fee(1, None).await?;
        let btc_vkb = smart_fee.fee_rate.map_or(0.00001f64, |rate| rate.to_btc());
        Ok((btc_vkb * 100_000_000.0 / 1000.0).ceil())
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxidWrapper(Txid);
impl From<TxidWrapper> for [u8; 32] {
    fn from(val: TxidWrapper) -> Self {
        val.0.to_byte_array()
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
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
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
                                return Err(anyhow::anyhow!(rpc_err.message));
                            }
                        }
                        _ => return Err(anyhow::anyhow!(e)),
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
    async fn get_last_finalized_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let block_count = self.client.get_block_count().await?;

        let finalized_blockhash = self
            .client
            .get_block_hash(block_count - FINALITY_DEPTH)
            .await?;

        let finalized_block_header = self.get_block_by_hash(finalized_blockhash).await?;

        Ok(finalized_block_header.header)
    }

    async fn subscribe_finalized_header(&self) -> Result<Self::HeaderStream, Self::Error> {
        unimplemented!()
    }

    // Fetch the head block of DA.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let best_blockhash = self.client.get_best_block_hash().await?;

        let head_block_header = self.get_block_by_hash(best_blockhash).await?;

        Ok(head_block_header.header)
    }

    // Extract the blob transactions relevant to a particular rollup from a block.
    #[instrument(level = "trace", skip_all)]
    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction> {
        debug!(
            "Extracting relevant txs from block {:?}",
            block.header.block_hash()
        );

        let txs = block.txdata.iter().map(|tx| tx.inner().clone()).collect();
        get_relevant_blobs_from_txs(txs, &self.rollup_name, &self.reveal_batch_prover_prefix)
    }

    /// Return a list of LightClient transactions in an unspecified order
    #[instrument(level = "trace", skip_all)]
    async fn extract_relevant_proofs(
        &self,
        block: &Self::FilteredBlock,
        prover_pk: &[u8],
    ) -> Vec<DaDataLightClient> {
        let mut completes = Vec::new();
        let mut aggregate_idxs = Vec::new();

        for tx in &block.txdata {
            if !tx
                .compute_wtxid()
                .to_byte_array()
                .as_slice()
                .starts_with(&self.reveal_light_client_prefix)
            {
                continue;
            }

            if let Ok(tx) = parse_light_client_transaction(&tx, &self.rollup_name) {
                match tx {
                    ParsedLightClientTransaction::Complete(complete) => {
                        if complete.public_key().as_ref() != prover_pk
                            && complete.get_sig_verified_hash().is_some()
                        {
                            // push only when signature is correct
                            completes.push(complete.body);
                        }
                    }
                    ParsedLightClientTransaction::Aggregate(aggregate) => {
                        if aggregate.public_key().as_ref() != prover_pk
                            && aggregate.get_sig_verified_hash().is_some()
                        {
                            // push only when signature is correct
                            // collect tx ids
                            aggregate_idxs.push(aggregate);
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
        for aggregate in &aggregate_idxs {
            let mut body = Vec::new();
            for txid in aggregate.txids().expect("Must contain tx ids; qed") {
                let tx_res = self
                    .client
                    .get_transaction(&txid, None)
                    .await
                    .expect("TODO handle errors");
                let tx = tx_res.transaction().expect("TODO err");
                let wrapped: TransactionWrapper = tx.into();
                let parsed = parse_light_client_transaction(&wrapped, &self.rollup_name)
                    .expect("Couldn't parse chunk");
                match parsed {
                    ParsedLightClientTransaction::Chunk(part) => {
                        body.extend(part.body);
                    }
                    ParsedLightClientTransaction::Complete(_)
                    | ParsedLightClientTransaction::Aggregate(_) => {
                        panic!("unexpected tx kind")
                    }
                }
            }
            aggregates.push(body);
        }

        let mut result = Vec::new();
        for blob in completes.into_iter().chain(aggregates) {
            let body = decompress_blob(&blob);
            match DaDataLightClient::try_from_slice(&body) {
                Ok(data) => {
                    result.push(data);
                }
                Err(e) => {
                    panic!("Couldn't parse body: {}", e);
                }
            }
        }
        result
    }

    #[instrument(level = "trace", skip_all)]
    async fn get_extraction_proof(
        &self,
        block: &Self::FilteredBlock,
        _blobs: &[<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction],
    ) -> (
        <Self::Spec as sov_rollup_interface::da::DaSpec>::InclusionMultiProof,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::CompletenessProof,
    ) {
        info!(
            "Getting extraction proof for block {:?}",
            block.header.block_hash()
        );

        let mut completeness_proof = Vec::with_capacity(block.txdata.len());

        let mut wtxids = Vec::with_capacity(block.txdata.len());
        wtxids.push([0u8; 32]);

        // coinbase starts with 0, so we skip it unless the prefix is all 0's
        if self.reveal_batch_prover_prefix.iter().all(|&x| x == 0) {
            completeness_proof.push(block.txdata[0].clone());
        }

        block.txdata[1..].iter().for_each(|tx| {
            let wtxid = tx.compute_wtxid().to_raw_hash().to_byte_array();

            // if tx_hash starts with the given prefix, it is in the completeness proof
            if wtxid.starts_with(&self.reveal_batch_prover_prefix) {
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

        (
            InclusionMultiProof::new(wtxids, block.txdata[0].clone(), coinbase_proof),
            completeness_proof,
        )
    }

    // Extract the list blob transactions relevant to a particular rollup from a block, along with inclusion and
    // completeness proofs for that set of transactions. The output of this method will be passed to the verifier.
    async fn extract_relevant_blobs_with_proof(
        &self,
        block: &Self::FilteredBlock,
    ) -> (
        Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction>,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::InclusionMultiProof,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::CompletenessProof,
    ) {
        info!(
            "Extracting relevant txs with proof from block {:?}",
            block.header.block_hash()
        );

        let txs = self.extract_relevant_blobs(block);
        let (inclusion_proof, completeness_proof) = self.get_extraction_proof(block, &txs).await;

        (txs, inclusion_proof, completeness_proof)
    }

    #[instrument(level = "trace", skip_all)]
    async fn send_transaction(
        &self,
        da_data: DaData,
    ) -> Result<<Self as DaService>::TransactionId, Self::Error> {
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

    async fn send_aggregated_zk_proof(
        &self,
        _aggregated_proof_data: &[u8],
    ) -> Result<u64, Self::Error> {
        unimplemented!();
    }

    async fn get_aggregated_proofs_at(&self, _height: u64) -> Result<Vec<Vec<u8>>, Self::Error> {
        unimplemented!();
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_fee_rate(&self) -> Result<u128, Self::Error> {
        let sat_vb_ceil = self.get_fee_rate_as_sat_vb_ceiled().await? as u128;

        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000
        let multiplied_fee = sat_vb_ceil.saturating_mul(2_500_000_000);
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(
        &self,
        hash: Self::BlockHash,
    ) -> Result<Self::FilteredBlock, Self::Error> {
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

    #[instrument(level = "trace", skip(self))]
    async fn get_relevant_blobs_of_pending_transactions(
        &self,
    ) -> Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction> {
        let pending_txs = self.get_pending_transactions().await.unwrap();
        get_relevant_blobs_from_txs(
            pending_txs,
            &self.rollup_name,
            &self.reveal_batch_prover_prefix,
        )
    }
}

fn get_relevant_blobs_from_txs(
    txs: Vec<Transaction>,
    rollup_name: &str,
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

        if let Ok(tx) = parse_batch_proof_transaction(&tx, rollup_name) {
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

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::sync::Arc;

    // use futures::{Stream, StreamExt};
    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::{BlockHash, CompactTarget};
    use sov_rollup_interface::da::{DaVerifier, SequencerCommitment};
    use sov_rollup_interface::services::da::{DaService, SlotData};

    use super::BitcoinService;
    use crate::helpers::parsers::parse_hex_transaction;
    use crate::helpers::test_utils::{get_mock_data, get_mock_txs};
    use crate::service::BitcoinServiceConfig;
    use crate::spec::block::BitcoinBlock;
    use crate::spec::header::HeaderWrapper;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::BitcoinVerifier;

    async fn get_service() -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/test".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                rollup_name: "sov-btc".to_string(),
                reveal_batch_prover_prefix: vec![1, 1],
                reveal_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        // let da_service = Arc::new(da_service);
        // da_service.clone().spawn_da_queue(rx);
        // da_service

        Arc::new(da_service)
    }

    async fn get_service_wrong_rollup_name() -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/other".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                rollup_name: "btc-sov".to_string(),
                reveal_batch_prover_prefix: vec![1, 1],
                reveal_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let da_service = Arc::new(da_service);

        da_service.clone().spawn_da_queue(rx);

        da_service
    }

    async fn get_service_correct_sig_different_public_key() -> Arc<BitcoinService> {
        let runtime_config = BitcoinServiceConfig {
            node_url: "http://localhost:38332/wallet/other2".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let da_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                rollup_name: "btc-sov".to_string(),
                reveal_batch_prover_prefix: vec![1, 1],
                reveal_light_client_prefix: vec![2, 2],
            },
            tx,
        )
        .await
        .expect("Error initialazing BitcoinService");

        let da_service = Arc::new(da_service);

        da_service.clone().spawn_da_queue(rx);

        da_service
    }

    #[tokio::test]
    #[ignore]
    /// A test we use to generate some data for the other tests
    async fn send_transaction() {
        use sov_rollup_interface::da::DaData;
        use sov_rollup_interface::zk::Proof;
        let da_service = get_service().await;

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [13; 32],
                l2_start_block_number: 1002,
                l2_end_block_number: 1100,
            }))
            .await
            .expect("Failed to send transaction");

        println!("sent 1");

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [14; 32],
                l2_start_block_number: 1101,
                l2_end_block_number: 1245,
            }))
            .await
            .expect("Failed to send transaction");

        println!("sent 2");

        println!("\n\nSend some BTC to this address: bcrt1qscttjdc3wypf7ttu0203sqgfz80a4q38cne693 and press enter\n\n");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();

        println!("sent 3");

        let size = 2000;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(Proof::Full(blob)))
            .await
            .expect("Failed to send transaction");

        println!("sent 4");

        println!("\n\nSend some BTC to this address: bcrt1qscttjdc3wypf7ttu0203sqgfz80a4q38cne693 and press enter\n\n");
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).unwrap();

        println!("sent 5");

        let size = 600 * 1024;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(Proof::Full(blob)))
            .await
            .expect("Failed to send transaction");

        println!("sent 6");

        // seq com different rollup name
        get_service_wrong_rollup_name()
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
            .send_transaction(DaData::ZKProof(Proof::Full(blob)))
            .await
            .expect("Failed to send transaction");

        println!("sent 7");

        // seq com incorrect pubkey and sig
        get_service_correct_sig_different_public_key()
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

        println!("sent 8");

        let size = 1200 * 1024;
        let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

        da_service
            .send_transaction(DaData::ZKProof(Proof::Full(blob)))
            .await
            .expect("Failed to send transaction");

        println!("sent 9");

        da_service
            .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
                merkle_root: [30; 32],
                l2_start_block_number: 1268,
                l2_end_block_number: 1314,
            }))
            .await
            .expect("Failed to send transaction");

        println!("sent 10");
    }

    // #[tokio::test]
    // async fn get_finalized_at() {
    //     let da_service = get_service().await;

    //     da_service
    //         .get_finalized_at(132)
    //         .await
    //         .expect("Failed to get block");
    // }

    // #[tokio::test]
    // async fn subscription_test() {
    //     // Setup and get the service
    //     let service = get_service().await;

    //     // Subscribe to the stream
    //     let mut stream = service.subscribe_finalized_header().await.unwrap();
    //     println!("Subscribed to finalized header stream");

    //     // Generate a new block and wait for the operation to complete
    //     service
    //         .client
    //         .generate_to_address(
    //             Address::from_str("bcrt1qxuds94z3pqwqea2p4f4ev4f25s6uu7y3avljrl")
    //                 .unwrap()
    //                 .require_network(bitcoin::Network::Regtest)
    //                 .unwrap(),
    //             1,
    //         )
    //         .await
    //         .unwrap();
    //     println!("Generated a new block");

    //     // Await the next item from the stream
    //     if let Some(header_result) = stream.next().await {
    //         println!("Got header: {:?}", header_result);
    //         assert!(header_result.is_ok());
    //     } else {
    //         panic!("Failed to receive header from stream");
    //     }
    // }

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

        let txs = da_service.extract_relevant_blobs(&block);

        assert_eq!(txs, relevant_txs);
    }

    #[tokio::test]
    async fn extract_relevant_blobs_with_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            da_service.extract_relevant_blobs_with_proof(&block).await;

        assert!(verifier
            .verify_relevant_tx_list(block.header(), &txs, inclusion_proof, completeness_proof)
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
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let incorrect_service = BitcoinService::new_without_wallet_check(
            runtime_config,
            RollupParams {
                rollup_name: "sov-btc".to_string(),
                reveal_batch_prover_prefix: vec![1, 1],
                reveal_light_client_prefix: vec![2, 2],
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
                    "69309c43aa5addfa0b3356e6eff316d2bdc3bf88e5e01575d2d2676c53677ca7",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "b03d88f57326ea63f1b241f70f45824446e10b3db3f0e808a60e0d7c013a8322",
                )
                .unwrap(),
                time: 1723819158,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 1,
            },
            3,
            1,
            WitnessMerkleNode::from_str(
                "8acc63c09983c9e8dba2e88b9e0218498ea4a3ff25ee8ce8be7674ada84046d5",
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

        let txs = da_service.extract_relevant_blobs(&block);

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
        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "4ebd11342b9d9e2a23b0f14c17a12bbb4f52a9290fe6a1cf313c270d5a49c2ea",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "a720804fbad45307b61958059c06f787a1ae10180ce91df2802a40023dea7e84",
                )
                .unwrap(),
                time: 1723820296,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 0,
            },
            3,
            2273,
            WitnessMerkleNode::from_str(
                "ab0edbf1611637701117cfc70b878b4196be1c5e4c256609ca8b620a0838860a",
            )
            .unwrap()
            .as_raw_hash()
            .to_byte_array(),
        );

        let txs_str = std::fs::read_to_string("test_data/mock_txs.txt").unwrap();

        let txdata: Vec<TransactionWrapper> = txs_str
            .lines()
            .map(|tx| parse_hex_transaction(tx).unwrap())
            .map(Into::into)
            .collect();

        let block = BitcoinBlock { header, txdata };

        let txs = da_service.extract_relevant_blobs(&block);

        assert_eq!(
            txs.first().unwrap().sender.0,
            da_pubkey,
            "Publickey recovered incorrectly!"
        );
    }
}
