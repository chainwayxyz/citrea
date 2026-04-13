//! This module provides fee-rate estimation for the Bitcoin DA service.
use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use bitcoincore_rpc::json::EstimateMode;
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;
use tracing::{instrument, trace};

const DEFAULT_MEMPOOL_SPACE_URL: &str = "https://mempool.space/";
const MEMPOOL_SPACE_PRECISE_FEE_ENDPOINT: &str = "api/v1/fees/precise";
const MEMPOOL_SPACE_TIMEOUT: Duration = Duration::from_secs(5);

type Result<T> = std::result::Result<T, FeeServiceError>;

/// Fee service error
#[derive(Error, Debug)]
pub enum FeeServiceError {
    /// Bitcoin RPC error.
    #[error("Bitcoin RPC error: {0}")]
    RpcError(#[from] bitcoincore_rpc::Error),

    /// Mempool space API request error.
    #[error("Mempool space API request failed: {0}")]
    MempoolSpaceRequestError(#[from] reqwest::Error),

    /// Mempool space API response parsing error.
    #[error("Failed to parse mempool space response")]
    MempoolSpaceParseError,
}

/// Service for retrieving Bitcoin fee rates.
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
        if self.network == bitcoin::Network::Regtest {
            tracing::debug!("Using default fee rate for regtest network: 1 sat/vb");
            return Ok(1.0);
        }

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
}

pub(crate) async fn get_fee_rate_from_mempool_space(mempool_space_url: &str) -> Result<f64> {
    // url should end with a slash and already contain network path
    // tolerate missing trailing slash by normalizing here
    let normalized_base_url = if mempool_space_url.ends_with('/') {
        mempool_space_url.to_string()
    } else {
        format!("{mempool_space_url}/")
    };
    let url = format!("{normalized_base_url}{MEMPOOL_SPACE_PRECISE_FEE_ENDPOINT}");

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
