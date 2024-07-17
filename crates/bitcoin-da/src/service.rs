// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashSet;

// use std::sync::Arc;
use async_trait::async_trait;
use bitcoin::consensus::encode;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, BlockHash, Transaction, Txid};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::DaSpec;
use sov_rollup_interface::services::da::{BlobWithNotifier, DaService};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tracing::{error, info, instrument, trace};

use crate::helpers::builders::{
    create_inscription_transactions, sign_blob_with_private_key, write_reveal_tx, TxWithId,
};
use crate::helpers::compression::{compress_blob, decompress_blob};
use crate::helpers::parsers::{parse_hex_transaction, parse_transaction};
use crate::rpc::{BitcoinNode, RPCError};
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header_stream::BitcoinHeaderStream;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::verifier::BitcoinVerifier;
use crate::REVEAL_OUTPUT_AMOUNT;

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug, Clone)]
pub struct BitcoinService {
    client: BitcoinNode,
    rollup_name: String,
    network: bitcoin::Network,
    da_private_key: Option<SecretKey>,
    reveal_tx_id_prefix: Vec<u8>,
    inscribes_queue: UnboundedSender<BlobWithNotifier<TxidWrapper>>,
}

/// Runtime configuration for the DA service
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DaServiceConfig {
    /// The URL of the Bitcoin node to connect to
    pub node_url: String,
    pub node_username: String,
    pub node_password: String,

    // network of the bitcoin node
    pub network: String,

    // da private key of the sequencer
    pub da_private_key: Option<String>,

    // number of last paid fee rates to average if estimation fails
    pub fee_rates_to_avg: Option<usize>,
}

const FINALITY_DEPTH: u64 = 4; // blocks
const POLLING_INTERVAL: u64 = 10; // seconds

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub async fn new(config: DaServiceConfig, chain_params: RollupParams) -> Self {
        let network =
            bitcoin::Network::from_str(&config.network).expect("Invalid bitcoin network name");

        let client = BitcoinNode::new(config.node_url, config.node_username, config.node_password);

        let private_key = config
            .da_private_key
            .map(|pk| SecretKey::from_str(&pk).expect("Invalid private key"));

        let (tx, mut rx) = unbounded_channel::<BlobWithNotifier<TxidWrapper>>();

        let this = Self::with_client(
            client,
            chain_params.rollup_name,
            network,
            private_key,
            chain_params.reveal_tx_id_prefix,
            tx,
        )
        .await;

        let serv = this.clone();

        // This is a queue of inscribe requests
        tokio::task::spawn_blocking(|| {
            let this = serv;
            tokio::runtime::Handle::current().block_on(async move {
                // TODO https://github.com/chainwayxyz/citrea/issues/537
                // TODO find last tx by utxo chain
                let mut prev_tx = match this.get_pending_transactions().await {
                    Ok(pending_txs) => {
                        if !pending_txs.is_empty() {
                            let tx = pending_txs.first().unwrap().clone();
                            let txid = tx.txid();
                            Some(TxWithId { tx, id: txid })
                        } else {
                            None
                        }
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
                    let prev = prev_tx.take();
                    loop {
                        // Build and send tx with retries:
                        let blob = request.blob.clone();
                        let fee_sat_per_vbyte = match this.get_fee_rate().await {
                            Ok(rate) => rate,
                            Err(e) => {
                                error!(?e, "Failed to call get_fee_rate. Retrying...");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        };
                        match this
                            .send_transaction_with_fee_rate(prev.clone(), blob, fee_sat_per_vbyte)
                            .await
                        {
                            Ok(tx) => {
                                let tx_id = TxidWrapper(tx.id);
                                info!(%tx.id, "Sent tx to BitcoinDA");
                                prev_tx = Some(tx);
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

        this
    }

    #[cfg(test)]
    pub async fn new_without_client(config: DaServiceConfig, chain_params: RollupParams) -> Self {
        let network =
            bitcoin::Network::from_str(&config.network).expect("Invalid bitcoin network name");

        let client = BitcoinNode::new(config.node_url, config.node_username, config.node_password);

        let private_key = config
            .da_private_key
            .map(|pk| SecretKey::from_str(&pk).expect("Invalid private key"));

        let (tx, _rx) = unbounded_channel();

        Self {
            client,
            rollup_name: chain_params.rollup_name,
            network,
            da_private_key: private_key,
            reveal_tx_id_prefix: chain_params.reveal_tx_id_prefix,
            inscribes_queue: tx,
        }
    }

    async fn with_client(
        client: BitcoinNode,
        rollup_name: String,
        network: bitcoin::Network,
        da_private_key: Option<SecretKey>,
        reveal_tx_id_prefix: Vec<u8>,
        inscribes_queue: UnboundedSender<BlobWithNotifier<TxidWrapper>>,
    ) -> Self {
        let wallets = client
            .list_wallets()
            .await
            .expect("Failed to list loaded wallets");

        if wallets.is_empty() {
            tracing::warn!("No loaded wallet found!");
        }

        Self {
            client,
            rollup_name,
            network,
            da_private_key,
            reveal_tx_id_prefix,
            inscribes_queue,
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_utxos(&self) -> Result<Vec<UTXO>, anyhow::Error> {
        let utxos = self.client.get_utxos().await?;
        if utxos.is_empty() {
            return Err(anyhow::anyhow!("There are no UTXOs"));
        }

        let utxos: Vec<UTXO> = utxos
            .into_iter()
            .filter(|utxo| utxo.spendable && utxo.solvable && utxo.amount > REVEAL_OUTPUT_AMOUNT)
            .collect();
        if utxos.is_empty() {
            return Err(anyhow::anyhow!("There are no spendable UTXOs"));
        }

        Ok(utxos)
    }

    #[instrument(level = "trace", skip_all, ret)]
    async fn get_pending_transactions(&self) -> Result<Vec<Transaction>, anyhow::Error> {
        let mut pending_utxos = self.client.get_pending_utxos().await?;
        // Sorted by ancestor count, the tx with the most ancestors is the latest tx
        pending_utxos.sort_unstable_by_key(|utxo| -(utxo.ancestor_count.unwrap_or(0) as i64));

        let mut pending_transactions = Vec::new();
        let mut scanned_txids = HashSet::new();

        for utxo in pending_utxos.iter() {
            let txid = utxo.txid.clone();
            // Check if tx is already in the pending transactions vector
            if scanned_txids.contains(&txid) {
                continue;
            }

            let raw_tx = self
                .client
                .get_raw_transaction(txid.clone())
                .await
                .expect("Transaction should exist with existing utxo");
            let parsed_tx = parse_hex_transaction(&raw_tx).expect("Rpc tx should be parsable");
            pending_transactions.push(parsed_tx);
            scanned_txids.insert(txid);
        }

        Ok(pending_transactions)
    }

    #[instrument(level = "trace", fields(prev_tx), ret, err)]
    pub async fn send_transaction_with_fee_rate(
        &self,
        prev_tx: Option<TxWithId>,
        blob: Vec<u8>,
        fee_sat_per_vbyte: f64,
    ) -> Result<TxWithId, anyhow::Error> {
        let client = self.client.clone();
        let network = self.network;

        let rollup_name = self.rollup_name.clone();
        let da_private_key = self.da_private_key.expect("No private key set");

        // Compress the blob
        let blob = compress_blob(&blob);

        // get all available utxos
        let utxos: Vec<UTXO> = self.get_utxos().await?;

        // get address from a utxo
        let address = Address::from_str(&utxos[0].address.clone())
            .unwrap()
            .require_network(network)
            .expect("Invalid network for address");

        // sign the blob for authentication of the sequencer
        let (signature, public_key) =
            sign_blob_with_private_key(&blob, &da_private_key).expect("Sequencer sign the blob");

        // create inscribe transactions
        let (unsigned_commit_tx, reveal_tx) = create_inscription_transactions(
            &rollup_name,
            blob,
            signature,
            public_key,
            prev_tx,
            utxos,
            address,
            REVEAL_OUTPUT_AMOUNT,
            fee_sat_per_vbyte,
            fee_sat_per_vbyte,
            network,
            self.reveal_tx_id_prefix.as_slice(),
        )?;

        // sign inscribe transactions
        let serialized_unsigned_commit_tx = &encode::serialize(&unsigned_commit_tx);
        let signed_raw_commit_tx = client
            .sign_raw_transaction_with_wallet(serialized_unsigned_commit_tx.encode_hex())
            .await?;

        // send inscribe transactions
        client.send_raw_transaction(signed_raw_commit_tx).await?;

        // serialize reveal tx
        let serialized_reveal_tx = &encode::serialize(&reveal_tx.tx);

        // write reveal tx to file, it can be used to continue revealing blob if something goes wrong
        write_reveal_tx(
            serialized_reveal_tx,
            unsigned_commit_tx.txid().to_raw_hash().to_string(),
        );

        // send reveal tx
        let reveal_tx_hash = client
            .send_raw_transaction(serialized_reveal_tx.encode_hex())
            .await?;

        info!("Blob inscribe tx sent. Hash: {}", reveal_tx_hash);

        Ok(reveal_tx)
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate(&self) -> Result<f64, anyhow::Error> {
        if self.network == bitcoin::Network::Regtest {
            // sometimes local mempool is empty, node cannot estimate
            return Ok(2.0);
        }

        self.client.estimate_smart_fee().await
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
pub struct TxidWrapper(Txid);
impl From<TxidWrapper> for [u8; 32] {
    fn from(val: TxidWrapper) -> Self {
        val.0.to_byte_array()
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
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        info!("Getting block at height {}", height);

        let block_hash;
        loop {
            block_hash = match self.client.get_block_hash(height).await {
                Ok(block_hash_response) => block_hash_response,
                Err(error) => {
                    match error.downcast_ref::<RPCError>() {
                        Some(error) => {
                            if error.code == -8 {
                                info!("Block not found, waiting");
                                tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL)).await;
                                continue;
                            } else {
                                // other error, return message
                                return Err(anyhow::anyhow!(error.message.clone()));
                            }
                        }
                        None => {
                            return Err(anyhow::anyhow!(error));
                        }
                    }
                }
            };

            break;
        }
        let block = self.client.get_block(block_hash).await?;

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

        let finalized_block_header = self.client.get_block_header(finalized_blockhash).await?;

        Ok(finalized_block_header)
    }

    async fn subscribe_finalized_header(&self) -> Result<Self::HeaderStream, Self::Error> {
        unimplemented!()
    }

    // Fetch the head block of DA.
    #[instrument(level = "trace", skip(self), err)]
    async fn get_head_block_header(
        &self,
    ) -> Result<<Self::Spec as DaSpec>::BlockHeader, Self::Error> {
        let best_blockhash = self.client.get_best_blockhash().await?;

        let head_block_header = self.client.get_block_header(best_blockhash).await?;

        Ok(head_block_header)
    }

    // Extract the blob transactions relevant to a particular rollup from a block.
    #[instrument(level = "trace", skip_all)]
    fn extract_relevant_blobs(
        &self,
        block: &Self::FilteredBlock,
    ) -> Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction> {
        info!(
            "Extracting relevant txs from block {:?}",
            block.header.block_hash()
        );

        let txs = block.txdata.iter().map(|tx| tx.inner().clone()).collect();
        get_relevant_blobs_from_txs(txs, &self.rollup_name, self.reveal_tx_id_prefix.as_slice())
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

        let mut txids = Vec::with_capacity(block.txdata.len());
        let mut wtxids = Vec::with_capacity(block.txdata.len());
        wtxids.push([0u8; 32]);
        let coinbase_tx_hash = block.txdata[0].txid().to_raw_hash().to_byte_array();
        txids.push(coinbase_tx_hash);
        if coinbase_tx_hash.starts_with(self.reveal_tx_id_prefix.as_slice()) {
            completeness_proof.push(block.txdata[0].clone());
        }

        block.txdata[1..].iter().for_each(|tx| {
            let txid = tx.txid().to_raw_hash().to_byte_array();
            let wtxid = tx.wtxid().to_raw_hash().to_byte_array();

            // if tx_hash has two leading zeros, it is in the completeness proof
            if txid.starts_with(self.reveal_tx_id_prefix.as_slice()) {
                completeness_proof.push(tx.clone());
            }

            wtxids.push(wtxid);
            txids.push(txid);
        });

        (
            InclusionMultiProof::new(txids, wtxids, block.txdata[0].clone()),
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
        blob: &[u8],
    ) -> Result<<Self as DaService>::TransactionId, Self::Error> {
        let queue = self.get_send_transaction_queue();
        let (tx, rx) = oneshot_channel();
        queue.send(BlobWithNotifier {
            blob: blob.to_vec(),
            notify: tx,
        })?;
        rx.await?
    }

    fn get_send_transaction_queue(&self) -> UnboundedSender<BlobWithNotifier<Self::TransactionId>> {
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
        // This already returns ceil, so the conversion should work
        let res = self.client.estimate_smart_fee().await? as u128;
        // multiply with 10^10/4 = 25*10^8 = 2_500_000_000
        let multiplied_fee = res.saturating_mul(2_500_000_000);
        Ok(multiplied_fee)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_block_by_hash(&self, hash: [u8; 32]) -> Result<Self::FilteredBlock, Self::Error> {
        info!("Getting block with hash {:?}", hash);

        let hash = BlockHash::from_byte_array(hash);

        let block = self.client.get_block(hash.to_string()).await?;
        Ok(block)
    }

    #[instrument(level = "trace", skip(self))]
    async fn get_relevant_blobs_of_pending_transactions(
        &self,
    ) -> Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction> {
        let pending_txs = self.get_pending_transactions().await.unwrap();
        get_relevant_blobs_from_txs(
            pending_txs,
            &self.rollup_name,
            self.reveal_tx_id_prefix.as_slice(),
        )
    }
}

fn get_relevant_blobs_from_txs(
    txs: Vec<Transaction>,
    rollup_name: &str,
    reveal_tx_id_prefix: &[u8],
) -> Vec<BlobWithSender> {
    let mut relevant_txs = Vec::new();

    for tx in txs {
        if !tx
            .txid()
            .to_byte_array()
            .as_slice()
            .starts_with(reveal_tx_id_prefix)
        {
            continue;
        }

        let parsed_inscription = parse_transaction(&tx, rollup_name);

        if let Ok(inscription) = parsed_inscription {
            if inscription.get_sig_verified_hash().is_some() {
                // Decompress the blob
                let decompressed_blob = decompress_blob(&inscription.body);

                let relevant_tx = BlobWithSender::new(
                    decompressed_blob,
                    inscription.public_key,
                    sha256d::Hash::hash(&inscription.body).to_byte_array(),
                );

                relevant_txs.push(relevant_tx);
            }
        }
    }
    relevant_txs
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    // use futures::{Stream, StreamExt};
    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::secp256k1::Keypair;
    use bitcoin::string::FromHexStr;
    use bitcoin::{BlockHash, CompactTarget};
    use sov_rollup_interface::da::DaVerifier;
    use sov_rollup_interface::services::da::{DaService, SlotData};

    use super::BitcoinService;
    use crate::helpers::parsers::parse_hex_transaction;
    use crate::helpers::test_utils::{get_mock_data, get_mock_txs};
    use crate::service::DaServiceConfig;
    use crate::spec::block::BitcoinBlock;
    use crate::spec::header::HeaderWrapper;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::BitcoinVerifier;

    async fn get_service() -> BitcoinService {
        let runtime_config = DaServiceConfig {
            node_url: "http://localhost:38332".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: "regtest".to_string(),
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        BitcoinService::new_without_client(
            runtime_config,
            RollupParams {
                rollup_name: "sov-btc".to_string(),
                reveal_tx_id_prefix: vec![0, 0],
            },
        )
        .await
    }

    // #[tokio::test]
    // async fn get_finalized_at() {
    //     let da_service = get_service().await;
    //
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

        assert_eq!(txs, relevant_txs)
    }

    #[tokio::test]
    async fn extract_relevant_blobs_with_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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

        let runtime_config = DaServiceConfig {
            node_url: "http://localhost:38332".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: "regtest".to_string(),
            da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33261".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: Some(2), // small to speed up tests
        };

        let incorrect_service = BitcoinService::new_without_client(
            runtime_config,
            RollupParams {
                rollup_name: "sov-btc".to_string(),
                reveal_tx_id_prefix: vec![0, 0],
            },
        )
        .await;

        let incorrect_pub_key =
            Keypair::from_secret_key(&secp, &incorrect_service.da_private_key.unwrap())
                .public_key()
                .serialize()
                .to_vec();

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "19bd253df7a58cb8131f223fa4d99db2ad4eee171b47e31c2b1a75d7c0c89ea6",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "478fd2a0d8b251d37bcda9b408d4b50a5b5387dedb9af1cfb16c0e543e8f2a9b",
                )
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            3,
            1,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
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
                    "427b67c04afcbbee6856b764535c512dc22d0eeef21a55ebb2a37157074563b7",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "574efcf98001bf273b489f3b5065cdd8b983ec9b9c31e001e2f3397a885911ca",
                )
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            3,
            2273,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
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
