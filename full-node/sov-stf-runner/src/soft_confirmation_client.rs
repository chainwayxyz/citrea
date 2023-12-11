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
        let raw_res: Result<Value, _> = self
            .client
            .request("ledger_getTransactionByNumber", rpc_params![num])
            .await
            .context("Failed to make RPC request")?;

        let body = raw_res
            .get("body")
            .context("Body field missing in response")?
            .as_array()
            .context("Body field is not an array")?
            .iter()
            // TODO: handle overflow from u64 to u8 https://github.com/chainwayxyz/secret-sovereign-sdk/issues/48
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();

        Ok(body)
    }
}
