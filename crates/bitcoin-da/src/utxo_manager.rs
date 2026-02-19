//! UTXO management for Bitcoin DA service.
//!
//! Handles UTXO selection and filtering. Supports two modes:
//! - Chained: Sequential transaction chains
//! - Oldest: Parallel chains using most-confirmed UTXOs

use std::collections::HashSet;
use std::sync::Arc;

use bitcoin::{Amount, Txid};
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::{Client, RpcApi};
use serde::{Deserialize, Serialize};
use sov_db::schema::types::da_jobs::DaJobStatus;

use crate::error::BitcoinServiceError;
use crate::monitoring::MonitoringService;
use crate::network_constants::NetworkConstants;
use crate::service::Result;
use crate::spec::utxo::UTXO;
use crate::REVEAL_OUTPUT_AMOUNT;

/// UTXO selection strategy when queue has pending transactions.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UtxoSelectionMode {
    /// Default behaviour, always use latest UTXO and keep transactions chained
    /// Maintain a single sequential transaction chain.
    Chained,
    /// Choose the UTXO with the highest amount of confirmations and run parallel UTXO chains
    Oldest,
}

impl Default for UtxoSelectionMode {
    fn default() -> Self {
        Self::Chained
    }
}

#[derive(Debug, Clone)]
/// UTXOs needed to build a transaction.
pub struct UtxoContext {
    /// Filtered UTXOs
    pub available_utxos: Vec<UTXO>,
    /// UTXO to chain from
    pub prev_utxo: Option<UTXO>,
}

/// Manages UTXO selection and filtering
///
/// Queries available UTXOs via bitcoin RPC, filters based on mode and queue state,
/// and ensures available UTXOs don't conflict with queued transactions.
#[derive(Debug)]
pub(crate) struct UtxoManager {
    client: Arc<Client>,
    monitoring: Arc<MonitoringService>,
    network_constants: NetworkConstants,
    pub mode: UtxoSelectionMode,
}

impl UtxoManager {
    pub fn new(
        client: Arc<Client>,
        monitoring: Arc<MonitoringService>,
        network_constants: NetworkConstants,
        mode: UtxoSelectionMode,
    ) -> Self {
        Self {
            client,
            monitoring,
            network_constants,
            mode,
        }
    }

    /// Returns filtered UTXOs and `prev_utxo`.
    pub async fn prepare_context(
        &self,
        job_status: &DaJobStatus,
        previous_job_in_progress: bool,
        sent_txids: &HashSet<Txid>,
    ) -> Result<UtxoContext> {
        let available_utxos = self.get_available_utxos(sent_txids).await?;

        let prev_utxo = match job_status {
            DaJobStatus::InProgress => None, // Will use previous reveal utxo in create_inscription_type_1
            _ => {
                self.select_prev_utxo(&available_utxos, previous_job_in_progress)
                    .await?
            }
        };

        Ok(UtxoContext {
            available_utxos,
            prev_utxo,
        })
    }

    /// Selects `prev_utxo` to use as first input in subsequent transaction.
    ///
    /// If queue is empty: uses latest monitored UTXO, that is the latest transaction in current UTXO chain.
    /// If queue has pending txs:
    /// - Chained mode: returns Err(BitcoinServiceError::QueueNotEmpty)
    /// - Oldest mode: uses UTXO with highest number of confirmation to start new chain
    pub(crate) async fn select_prev_utxo(
        &self,
        available_utxos: &[UTXO],
        previous_job_in_progress: bool,
    ) -> Result<Option<UTXO>> {
        let prev_utxo = self.get_prev_utxo().await;
        if !previous_job_in_progress {
            return Ok(prev_utxo);
        }

        match self.mode {
            UtxoSelectionMode::Chained => {
                // Prevent UTXO conflicts when queue is not empty and running UtxoSelectionMode::Chained mode
                Err(BitcoinServiceError::PreviousJobInProgress)
            }
            UtxoSelectionMode::Oldest => Ok(
                // Get UTXO with most confirmations to start new chain
                available_utxos
                    .iter()
                    .max_by_key(|utxo| utxo.confirmations)
                    .cloned(),
            ),
        }
    }

    /// Retrieves the most recent spendable UTXO from the transaction chain.
    pub(crate) async fn get_prev_utxo(&self) -> Option<UTXO> {
        let (txid, tx) = self.monitoring.get_last_tx().await?;

        let utxos = tx.to_utxos()?;

        // Check that tx out is still spendable
        // If not found, utxo is already spent
        self.client.get_tx_out(&txid, 0, Some(true)).await.ok()??;

        // Return first vout
        utxos.into_iter().next()
    }

    /// Gets available UTXOs from `list_unspent` RPC, and filter by mode.
    pub(crate) async fn get_available_utxos(
        &self,
        sent_txids: &HashSet<Txid>,
    ) -> Result<Vec<UTXO>> {
        let utxos = self
            .client
            .list_unspent(Some(0), None, None, None, None)
            .await?;
        if utxos.is_empty() {
            return Err(BitcoinServiceError::MissingUTXO);
        }

        let filtered_utxos = match self.mode {
            UtxoSelectionMode::Chained => self.chained_mode_filter(utxos).await,
            UtxoSelectionMode::Oldest => self.oldest_mode_filter(utxos, sent_txids).await,
        };

        if filtered_utxos.is_empty() {
            return Err(BitcoinServiceError::MissingSpendableUTXO);
        }

        Ok(filtered_utxos)
    }

    /// Filters UTXOs for Chained mode.
    async fn chained_mode_filter(&self, utxos: Vec<ListUnspentResultEntry>) -> Vec<UTXO> {
        let commit_txids = self
            .monitoring
            .get_in_mempool_commit_transaction_ids()
            .await;

        utxos
            .into_iter()
            .filter(|utxo| {
                utxo.spendable
                            && utxo.solvable
                            // Accept either safe utxos OR unsafe commit change output that are monitored (and can be considered `mine` and thus safe)
                            && (utxo.safe || (commit_txids.contains(&utxo.txid) && utxo.vout == 1))
                            && utxo.amount > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
            })
            .map(Into::into)
            .collect()
    }

    /// Filters UTXOs for Oldest mode.
    async fn oldest_mode_filter(
        &self,
        utxos: Vec<ListUnspentResultEntry>,
        sent_txids: &HashSet<Txid>,
    ) -> Vec<UTXO> {
        // When running in UtxoSelectionMode::Oldest, we're creating multiple utxos chain in parallel
        // to be able to send multiple proofs in the same block without hitting mempool policy limits.
        // To make sure there are no conflicts between parallel utxos chain,
        // this additional filters out any UTXO used by queued txs and any change UTXO that are not finalized
        utxos
            .into_iter()
            .filter(|utxo| {
                utxo.spendable
                    && utxo.solvable
                    && utxo.safe
                    && utxo.amount > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
                    // Remove utxo already in use by queued txs
                    && !sent_txids.contains(&utxo.txid)
                    // Only keep finalized change output
                    && (utxo.vout == 0
                        || utxo.confirmations as u64 >= self.network_constants.finality_depth)
            })
            .map(Into::into)
            .collect()
    }
}
