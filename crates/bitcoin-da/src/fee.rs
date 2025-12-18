//! This module provides a service for managing Bitcoin transaction fees.

use core::result::Result::Ok;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, Network, Sequence, Txid};
use bitcoincore_rpc::json::{
    BumpFeeResult, CreateRawTransactionInput, EstimateMode, WalletCreateFundedPsbtOptions,
};
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;
use tracing::{debug, instrument, trace, warn};

use crate::error::BitcoinServiceError;
use crate::monitoring::{MonitoredTx, MonitoredTxKind};
use crate::spec::utxo::UTXO;
use crate::tx_signer::SignedTxPair;
use crate::utxo_manager::UtxoContext;

const DEFAULT_MEMPOOL_SPACE_URL: &str = "https://mempool.space/";
const MEMPOOL_SPACE_PRECISE_FEE_ENDPOINT: &str = "api/v1/fees/precise";
const MEMPOOL_SPACE_TIMEOUT: Duration = Duration::from_secs(5);

const BASE_FEE_RATE_MULTIPLIER: f64 = 1.0;
const FEE_RATE_MULTIPLIER_FACTOR: f64 = 1.1;
const MAX_FEE_RATE_MULTIPLIER: f64 = 2.0;

/// Type alias for a Partially Signed Bitcoin Transaction (PSBT).
pub type Psbt = String;

type Result<T> = std::result::Result<T, FeeServiceError>;

/// Fee service error
#[derive(Error, Debug)]
pub enum FeeServiceError {
    /// Attempt to bump commit transaction without force flag.
    #[error("Cannot bump commit transaction fee without force flag")]
    CommitBumpNotAllowed,

    /// RBF not supported for this transaction type.
    #[error("RBF only supported on CPFP transactions")]
    RbfNotSupported,

    /// Failed to retrieve PSBT from bumpfee RPC.
    #[error("Failed to retrieve PSBT from bumpfee RPC")]
    PsbtRetrievalFailure,

    /// Bitcoin RPC error.
    #[error("Bitcoin RPC error: {0}")]
    RpcError(#[from] bitcoincore_rpc::Error),

    /// Bitcoin amount parsing error.
    #[error("Bitcoin amount error: {0}")]
    AmountError(#[from] bitcoin::amount::ParseAmountError),

    /// Invalid network for address.
    #[error("Invalid network for address")]
    InvalidAddressNetwork,

    /// Missing address in UTXO.
    #[error("Missing address in UTXO")]
    MissingUtxoAddress,

    /// Mempool space API request error.
    #[error("Mempool space API request failed: {0}")]
    MempoolSpaceRequestError(#[from] reqwest::Error),

    /// Mempool space API response parsing error.
    #[error("Failed to parse mempool space response")]
    MempoolSpaceParseError,
}

/// Method to bump the fee of a transaction.
/// It can be done using Child Pays for Parent (CPFP) or Replace-by-Fee (RBF).
pub enum BumpFeeMethod {
    /// Child Pays for Parent (CPFP) method.
    Cpfp,
    /// Replace-by-Fee (RBF) method.
    Rbf,
}

/// Service for managing Bitcoin transaction fees.
/// It provides methods to get the current fee rate, bump transaction fees,
/// and handle fee-related operations.
#[derive(Debug)]
pub struct FeeService {
    client: Arc<Client>,
    network: Network,
    mempool_space_url: String,
}

impl FeeService {
    /// Create a new instance of `FeeService`.
    pub fn new(
        client: Arc<Client>,
        network: bitcoin::Network,
        mempool_space_url: Option<String>,
    ) -> Self {
        let mempool_space_url =
            mempool_space_url.unwrap_or_else(|| DEFAULT_MEMPOOL_SPACE_URL.to_string());
        Self {
            client,
            network,
            mempool_space_url,
        }
    }

    /// Get the fee rate in sat/vB from the mempool space or via the Bitcoin Core client.
    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate(&self) -> Result<f64> {
        // If network is regtest or signet, mempool space is not available
        let sat_vkb = match get_fee_rate_from_mempool_space(&self.mempool_space_url).await {
            Ok(fee_rate) => fee_rate,
            Err(e) => {
                tracing::error!(?e, "Failed to get fee rate from mempool.space");
                self.client
                    .estimate_smart_fee(1, Some(EstimateMode::Conservative))
                    .await?
                    .fee_rate
                    .map(|rate| rate.to_sat() as f64)
                    .unwrap_or(1000.0)
            }
        };

        let sat_vb = sat_vkb / 1000.0;
        tracing::debug!("Fee rate: {} sat/vb", sat_vb);
        Ok(sat_vb)
    }

    /// Bump TX fee via cpfp.
    pub async fn bump_fee_cpfp(
        &self,
        monitored_tx: &MonitoredTx,
        parent_txid: &Txid,
        fee_rate: f64,
        force: Option<bool>,
        utxo: UTXO,
    ) -> Result<Psbt> {
        let force = force.unwrap_or_default();
        match (monitored_tx.kind, force) {
            (MonitoredTxKind::Commit, false) => return Err(FeeServiceError::CommitBumpNotAllowed),
            (MonitoredTxKind::Commit, true) => {
                warn!("Force creating CPFP TX for commit TX {parent_txid}");
            }
            _ => debug!("Creating CPFP TX for {parent_txid}"),
        }

        let parent_tx = &monitored_tx.tx;
        let change_address = utxo
            .address
            .clone()
            .ok_or(FeeServiceError::MissingUtxoAddress)?
            .require_network(self.network)
            .map_err(|_| FeeServiceError::InvalidAddressNetwork)?;

        let mut outputs = HashMap::new();
        outputs.insert(change_address.to_string(), parent_tx.output[0].value);
        let options = WalletCreateFundedPsbtOptions {
            add_inputs: Some(true),
            fee_rate: Some(Amount::from_btc(fee_rate / 100_000.0)?), // sat/vB to BTC/kB
            replaceable: Some(true),
            ..Default::default()
        };

        let funded_psbt = self
            .client
            .wallet_create_funded_psbt(
                &[CreateRawTransactionInput {
                    txid: utxo.tx_id,
                    vout: utxo.vout,
                    sequence: Some(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32()),
                }],
                &outputs,
                None,
                Some(options),
                None,
            )
            .await?;

        Ok(funded_psbt.psbt)
    }

    /// Bump TX fee via rbf.
    pub async fn bump_fee_rbf(&self, kind: MonitoredTxKind, parent_txid: &Txid) -> Result<Psbt> {
        match kind {
            MonitoredTxKind::Cpfp => {}
            _ => return Err(FeeServiceError::RbfNotSupported), // TODO Add support for bumping reveal TX
        }

        let BumpFeeResult {
            psbt: Some(funded_psbt),
            ..
        } = self.client.psbt_bump_fee(parent_txid, None).await?
        else {
            return Err(FeeServiceError::PsbtRetrievalFailure);
        };

        Ok(funded_psbt)
    }

    /// Get the base fee rate multiplier.
    /// This is used to calculate the next fee rate multiplier based on the current one.
    pub fn base_fee_rate_multiplier(&self) -> f64 {
        BASE_FEE_RATE_MULTIPLIER
    }

    /// Get the next fee rate multiplier based on the current multiplier.
    /// It multiplies the current multiplier by a factor.
    pub fn get_next_fee_rate_multiplier(&self, multiplier: f64) -> f64 {
        (multiplier * FEE_RATE_MULTIPLIER_FACTOR).min(MAX_FEE_RATE_MULTIPLIER)
    }
}

pub(crate) async fn get_fee_rate_from_mempool_space(mempool_space_url: &str) -> Result<f64> {
    // url should end with a slash
    // it should already contain network path
    let url = format!("{mempool_space_url}{MEMPOOL_SPACE_PRECISE_FEE_ENDPOINT}");

    let response = get_with_timeout(url.clone(), MEMPOOL_SPACE_TIMEOUT)
        .await
        .map_err(|e| {
            trace!("Failed to fetch from {}: {:?}", url, e);
            FeeServiceError::MempoolSpaceParseError
        })?;

    let json = response.json::<serde_json::Value>().await.map_err(|e| {
        trace!("Failed to parse JSON from {}: {:?}", url, e);
        FeeServiceError::MempoolSpaceParseError
    })?;

    let fee_rate = json
        .get("fastestFee")
        .and_then(|fee| fee.as_f64())
        .ok_or(FeeServiceError::MempoolSpaceParseError)?;

    Ok(fee_rate * 1000.0)
}

pub(crate) fn validate_txs_fee_rate(
    txs: &[SignedTxPair],
    fee_rate: f64,
    utxo_context: UtxoContext,
) -> std::result::Result<(), BitcoinServiceError> {
    let mut utxo_map = utxo_context
        .available_utxos
        .into_iter()
        .map(|utxo| ((utxo.tx_id, utxo.vout), Amount::from_sat(utxo.amount)))
        .collect::<HashMap<_, _>>();
    if let Some(prev_utxo) = utxo_context.prev_utxo {
        utxo_map.insert(
            (prev_utxo.tx_id, prev_utxo.vout),
            Amount::from_sat(prev_utxo.amount),
        );
    }

    for tx in txs {
        // Validate commit
        let commit_tx = &tx.commit.tx;
        let input_amount: Amount = commit_tx
            .input
            .iter()
            .flat_map(|input| {
                utxo_map
                    .get(&(input.previous_output.txid, input.previous_output.vout))
                    .cloned()
            })
            .sum();
        let output_amount = commit_tx.output.iter().map(|tx| tx.value).sum();

        if (input_amount - output_amount) < Amount::from_sat(commit_tx.vsize() as u64) {
            return Err(BitcoinServiceError::FeeCalculation(fee_rate));
        }

        // Add commit change output to utxo_map
        if let Some(change_output) = commit_tx.output.get(1) {
            utxo_map.insert((tx.commit_txid(), 1), change_output.value);
        }

        // Validate reveal
        let reveal_tx = &tx.reveal.tx;
        let input_amount = commit_tx.output[0].value;
        let output_amount = reveal_tx.output[0].value;

        // Add reveal utxo to utxo_map, used by chunking txs
        utxo_map.insert((tx.reveal_txid(), 0), output_amount);

        if (input_amount - output_amount) < Amount::from_sat(reveal_tx.vsize() as u64) {
            return Err(BitcoinServiceError::FeeCalculation(fee_rate));
        }
    }

    Ok(())
}

async fn get_with_timeout<T: reqwest::IntoUrl>(
    url: T,
    timeout: Duration,
) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(url)
        .send()
        .await
}

#[cfg(test)]
mod tests {

    use super::{get_fee_rate_from_mempool_space, DEFAULT_MEMPOOL_SPACE_URL};

    #[tokio::test]
    async fn test_mempool_space_fee_rate() {
        let mempool_space_url = DEFAULT_MEMPOOL_SPACE_URL;

        let _fee_rate = get_fee_rate_from_mempool_space(mempool_space_url)
            .await
            .unwrap();
    }
}
