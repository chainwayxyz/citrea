use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use citrea_common::PricingServiceConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Response structure for the pricing API
#[derive(Debug, Serialize, Deserialize)]
pub struct PriceResponse {
    pub min_price: u64,
    pub max_price: u64,
    pub lock_timeout: u64,
    pub max_possible_price: u64,
    pub lock_stake: u64,
    pub ramp_up_period: u64,
    pub timeout: u64,
    pub bidding_start: u64,
}

/// Service for fetching pricing information from the pricing API
#[derive(Clone)]
pub struct PricingService {
    client: Client,
    base_url: String,
}

impl PricingService {
    /// Create a new instance of `PricingService` from configuration
    ///
    /// # Arguments
    /// * `config` - Pricing service configuration
    pub fn from_config(config: &PricingServiceConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        info!(
            "Pricing service initialized with URL: {} (timeout: {}s)",
            config.base_url, config.timeout_secs
        );

        Self {
            client,
            base_url: config.base_url.clone(),
        }
    }

    /// Fetch pricing information for the given number of cycles
    ///
    /// # Arguments
    /// * `cycles` - Number of cycles to get pricing for
    ///
    /// # Returns
    /// * `Result<PriceResponse>` - Pricing information or error
    pub async fn get_price(&self, cycles: u64) -> Result<PriceResponse> {
        let url = format!("{}/api/pricing", self.base_url);

        info!("Fetching price for {} cycles", cycles);

        let response = self
            .client
            .get(&url)
            .query(&[("cycles", cycles)])
            .send()
            .await
            .context("Failed to send request to pricing service")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Pricing service returned error status {}: {}",
                status,
                body
            ));
        }

        let price_response: PriceResponse = response
            .json()
            .await
            .context("Failed to parse pricing response as JSON")?;

        info!("Received pricing response: {:?}", price_response);

        Ok(price_response)
    }
}
