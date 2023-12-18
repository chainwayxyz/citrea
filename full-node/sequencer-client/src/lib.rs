use anyhow::Context;
use ethers::types::{Bytes, H256};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde_json::Value;
use tracing::info;

/// Configuration for SequencerClient.
#[derive(Debug, Clone)]
pub struct SequencerClient {
    /// Start height for soft confirmation
    pub start_height: u64,
    /// Host config for soft confirmation
    pub rpc_url: String,
    /// Client object for soft confirmation
    pub client: HttpClient,
}

impl SequencerClient {
    /// Creates the sequencer client
    pub fn new(start_height: u64, rpc_url: String) -> Self {
        let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
        Self {
            start_height,
            rpc_url,
            client,
        }
    }

    /// Gets l2 block given l2 height
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

    /// Sends raw tx to sequencer
    pub async fn send_raw_tx(&self, tx: Bytes) -> anyhow::Result<H256> {
        let tx_hash: H256 = self
            .client
            .request("eth_sendRawTransaction", rpc_params![tx])
            .await?;
        Ok(tx_hash)
    }
}
