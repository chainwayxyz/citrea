use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
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
use citrea_common::utils::read_env;
use citrea_primitives::compression::{compress_blob, decompress_blob};
use citrea_primitives::MAX_TXBODY_SIZE;
use metrics::histogram;
use reth_tasks::shutdown::GracefulShutdown;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaSpec, DaTxRequest, DataOnDa, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use sov_rollup_interface::zk::Proof;
use sov_rollup_interface::Network;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot::channel as oneshot_channel;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::error::BitcoinServiceError;
use crate::fee::{BumpFeeMethod, FeeService};
use crate::helpers::builders::body_builders::{
    backup_chunked_txs, backup_complete_txs, create_light_client_transactions, DaTxs, RawTxData,
};
use crate::helpers::builders::test_utils::{
    test_create_single_aggregate, test_create_single_chunk,
};
use crate::helpers::builders::TxWithId;
use crate::helpers::merkle_tree;
use crate::helpers::merkle_tree::BitcoinMerkleTree;
use crate::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use crate::monitoring::{MonitoredTxKind, MonitoringConfig, MonitoringService, TxStatus};
use crate::network_constants::{get_network_constants, NetworkConstants};
use crate::service::{split_proof, BitcoinService, Result};
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::header::HeaderWrapper;
use crate::spec::header_stream::BitcoinHeaderStream;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::short_proof::BitcoinHeaderShortProof;
use crate::spec::transaction::TransactionWrapper;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::verifier::{BitcoinVerifier, WITNESS_COMMITMENT_PREFIX};
use crate::REVEAL_OUTPUT_AMOUNT;

impl BitcoinService {
    pub async fn test_send_separate_chunk_transaction_with_fee_rate(
        &self,
        tx_request: DaTxRequest,
        fee_sat_per_vbyte: u64,
    ) -> Result<Vec<Txid>> {
        let network = self.network;

        let da_private_key = self.da_private_key.expect("No private key set");

        match tx_request {
            DaTxRequest::ZKProof(zkproof) => {
                let mut txids = vec![];
                let data = split_proof(zkproof)?;

                let reveal_light_client_prefix = self.reveal_tx_prefix.clone();
                // create inscribe transactions
                let mut reveal_chunks = vec![];
                match data {
                    RawTxData::Chunks(chunks) => {
                        for body in chunks {
                            // get all available utxos that are not already spent
                            let utxos = self.get_utxos().await?;
                            let utxos = utxos
                                .into_iter()
                                .filter(|utxo| utxo.amount >= 50 * (10 as u64).pow(8))
                                .collect::<Vec<_>>();

                            let prev_utxo = self.get_prev_utxo().await;

                            // get address from a utxo
                            let address = utxos[0]
                                .address
                                .clone()
                                .context("Missing address")?
                                .require_network(network)?;

                            let (chunk_commit, chunk_reveal) = test_create_single_chunk(
                                body,
                                &da_private_key,
                                prev_utxo,
                                utxos,
                                address,
                                fee_sat_per_vbyte,
                                fee_sat_per_vbyte,
                                network,
                                &reveal_light_client_prefix,
                            )?;

                            reveal_chunks.push(chunk_reveal.clone());
                            // Send chunks as if they were complete txs separate from each other
                            txids.extend(
                                self.send_complete_transaction(
                                    chunk_commit,
                                    TxWithId {
                                        id: chunk_reveal.compute_txid(),
                                        tx: chunk_reveal,
                                    },
                                    self.tx_backup_dir.clone(),
                                    "complete_zk_proof",
                                )
                                .await?,
                            );
                        }
                        // Now send the aggregate data
                        let (reveal_tx_ids, reveal_wtx_ids): (Vec<_>, Vec<_>) = reveal_chunks
                            .iter()
                            .map(|tx| {
                                (
                                    tx.compute_txid().to_byte_array(),
                                    tx.compute_wtxid().to_byte_array(),
                                )
                            })
                            .collect();
                        let aggregate = DataOnDa::Aggregate(reveal_tx_ids, reveal_wtx_ids);
                        // To sign the list of tx ids we assume they form a contigious list of bytes
                        let reveal_body: Vec<u8> =
                            borsh::to_vec(&aggregate).expect("Aggregate serialize must not fail");

                        // get all available utxos that are not already spent
                        let utxos = self.get_utxos().await?;
                        let utxos = utxos
                            .into_iter()
                            .filter(|utxo| utxo.amount >= 50 * (10 as u64).pow(8))
                            .collect::<Vec<_>>();
                        let prev_utxo = self.get_prev_utxo().await;

                        // get address from a utxo
                        let address = utxos[0]
                            .address
                            .clone()
                            .context("Missing address")?
                            .require_network(network)?;

                        let (aggr_commit, aggr_reveal) = test_create_single_aggregate(
                            reveal_body,
                            &da_private_key,
                            utxos,
                            address,
                            network,
                            fee_sat_per_vbyte,
                            fee_sat_per_vbyte,
                            prev_utxo,
                            &self.reveal_tx_prefix,
                        )?;

                        txids.extend(
                            self.send_complete_transaction(
                                aggr_commit,
                                TxWithId {
                                    id: aggr_reveal.compute_txid(),
                                    tx: aggr_reveal,
                                },
                                self.tx_backup_dir.clone(),
                                "complete_zk_proof",
                            )
                            .await?,
                        );
                    }
                    _ => {
                        return Err(BitcoinServiceError::InvalidTransaction(
                            "Expected chunks only for this function".to_string(),
                        ))
                    }
                }
            }
            _ => {
                return Err(BitcoinServiceError::InvalidTransaction(
                    "Expected chunk zk proof".to_owned(),
                ))
            }
        }

        Ok(vec![])
    }
}
