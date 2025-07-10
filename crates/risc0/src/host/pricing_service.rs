use std::env;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Response structure for the pricing API
#[derive(Debug, Serialize, Deserialize)]
pub struct PriceResponse {
    pub min_price: u64,
    pub max_price: u64,
    pub lock_timeout: u64,
    pub max_possible_price: u64,
}

/// Service for fetching pricing information from the pricing API
#[derive(Clone)]
pub struct PricingService {
    client: Client,
    base_url: String,
}

impl PricingService {
    /// Create a new instance of `PricingService`
    /// Reads the base URL from the `PRICING_SERVICE_URL` environment variable
    pub fn new() -> Self {
        let base_url = env::var("PRICING_SERVICE_URL")
            .expect("PRICING_SERVICE_URL environment variable not set");

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        info!("Pricing service initialized with URL: {}", base_url);

        Self { client, base_url }
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

        debug!("Fetching price for {} cycles", cycles);

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

        debug!("Received pricing response: {:?}", price_response);

        Ok(price_response)
    }
}
