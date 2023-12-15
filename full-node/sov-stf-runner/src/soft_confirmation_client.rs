use anyhow::Context;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde_json::Value;

/// Configuration for SoftConfirmationClient.
#[derive(Debug, Clone)]
pub struct SoftConfirmationClient {
    /// Start height for soft confirmation
    pub start_height: u64,
    /// Host config for soft confirmation
    pub rpc_url: String,
    /// Client object for soft confirmation
    pub client: HttpClient,
}

impl SoftConfirmationClient {
    pub fn new(start_height: u64, rpc_url: String) -> Self {
        let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
        Self {
            start_height,
            rpc_url,
            client,
        }
    }

    pub async fn get_sov_tx(&self, num: u64) -> anyhow::Result<Vec<u8>> {
        let raw_res: Value = self
            .client
            .request("ledger_getTransactionByNumber", rpc_params![num])
            .await
            .context("Failed to make RPC request")?;

        let vals = raw_res
            .get("body")
            .context("Body field missing in response")?
            .as_array()
            .context("Body field is not an array")?;

        let mut body = vec![];

        for val in vals.iter() {
            body.push(u8::try_from(
                val.as_u64().context("Failed to convert Value to u64")?,
            )?);
        }

        Ok(body)
    }
}
