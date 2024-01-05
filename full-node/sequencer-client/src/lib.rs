use ethers::types::{Bytes, H256};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::Error;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde::Deserialize;

/// Configuration for SequencerClient.
#[derive(Debug, Clone)]
pub struct SequencerClient {
    /// Host config for soft confirmation
    pub rpc_url: String,
    /// Client object for soft confirmation
    pub client: HttpClient,
}

impl SequencerClient {
    /// Creates the sequencer client
    pub fn new(rpc_url: String) -> Self {
        let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
        Self { rpc_url, client }
    }

    /// Gets l2 block given l2 height
    pub async fn get_soft_batch<DaSpec: sov_rollup_interface::da::DaSpec>(
        &self,
        num: u64,
    ) -> anyhow::Result<Option<GetSoftBatchResponse<DaSpec::SlotHash>>> {
        let res: Result<Option<GetSoftBatchResponse<DaSpec::SlotHash>>, jsonrpsee::core::Error> =
            self.client
                .request("ledger_getSoftBatchByNumber", rpc_params![num])
                .await;

        match res {
            Ok(res) => Ok(res),
            Err(e) => match e {
                Error::Transport(e) => anyhow::Result::Err(Error::Transport(e).into()),
                Error::ParseError(e) => anyhow::Result::Err(Error::ParseError(e).into()),
                _ => Err(anyhow::anyhow!(e)),
            },
        }
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

#[derive(Deserialize, Debug)]
pub struct GetSoftBatchResponse<Hash> {
    pub da_slot_height: u64,
    pub da_slot_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<Vec<u8>>>,
    pub pre_state_root: Vec<u8>,
    pub post_state_root: Vec<u8>,
}
