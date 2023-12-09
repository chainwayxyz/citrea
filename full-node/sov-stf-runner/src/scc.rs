use anyhow::Context;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde_json::Value;

/// Configuration for StateTransitionRunner.
#[derive(Debug, Clone)]
pub struct SoftConfirmationClient {
    /// Start height for soft confirmation
    pub start_height: u64,
    /// Host config for soft confirmation
    pub rpc_host: String,
    /// Port config for soft confirmation
    pub rpc_port: u16,
    /// Client object for soft confirmation
    pub client: HttpClient,
}

impl SoftConfirmationClient {
    pub fn new(start_height: u64, host_config: String, port_config: u16) -> Self {
        let client = HttpClientBuilder::default()
            .build(format!("http://{}:{}", host_config, port_config))
            .unwrap();
        Self {
            start_height,
            rpc_host: host_config,
            rpc_port: port_config,
            client,
        }
    }

    pub async fn get_sov_tx(&self, num: u64) -> anyhow::Result<Vec<u8>> {
        let raw_res: Result<Value, _> = self
            .client
            .request("ledger_getTransactionByNumber", rpc_params![num])
            .await
            .context("Failed to make RPC request");

        let body = raw_res?
            .get("body")
            .context("Body field missing in response")?
            .as_array()
            .context("Body field is not an array")?
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();

        Ok(body)
    }
}
