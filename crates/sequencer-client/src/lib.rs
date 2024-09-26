use std::ops::RangeInclusive;

use citrea_primitives::types::SoftConfirmationHash;
use jsonrpsee::core::client::{ClientT, Error};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use reth_primitives::{Bytes, B256};
use serde::Deserialize;
use sov_rollup_interface::rpc::HexTx;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use tracing::instrument;

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
    #[instrument(level = "trace")]
    pub fn new(rpc_url: String) -> Self {
        let client = HttpClientBuilder::default().build(&rpc_url).unwrap();
        Self { rpc_url, client }
    }

    /// Gets l2 block given l2 height
    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn get_soft_confirmation<DaSpec: sov_rollup_interface::da::DaSpec>(
        &self,
        num: u64,
    ) -> anyhow::Result<Option<GetSoftConfirmationResponse>> {
        let res: Result<Option<GetSoftConfirmationResponse>, Error> = self
            .client
            .request("ledger_getSoftConfirmationByNumber", rpc_params![num])
            .await;

        match res {
            Ok(res) => Ok(res),
            Err(e) => match e {
                Error::Transport(e) => anyhow::Result::Err(Error::Transport(e).into()),
                _ => Err(anyhow::anyhow!(e)),
            },
        }
    }

    /// Gets l2 blocks given a range
    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn get_soft_confirmation_range<DaSpec: sov_rollup_interface::da::DaSpec>(
        &self,
        range: RangeInclusive<u64>,
    ) -> anyhow::Result<Vec<Option<GetSoftConfirmationResponse>>> {
        let res: Result<Vec<Option<GetSoftConfirmationResponse>>, Error> = self
            .client
            .request(
                "ledger_getSoftConfirmationRange",
                rpc_params![range.start(), range.end()],
            )
            .await;

        match res {
            Ok(res) => Ok(res),
            Err(e) => match e {
                Error::Transport(e) => anyhow::Result::Err(Error::Transport(e).into()),
                _ => Err(anyhow::anyhow!(e)),
            },
        }
    }

    /// Gets l2 block height
    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn block_number(&self) -> Result<u64, Error> {
        self.client
            .request("ledger_getHeadSoftConfirmationHeight", rpc_params![])
            .await
    }

    /// Sends raw tx to sequencer
    #[instrument(level = "trace", skip_all, err, ret)]
    pub async fn send_raw_tx(&self, tx: Bytes) -> Result<B256, Error> {
        self.client
            .request("eth_sendRawTransaction", rpc_params![tx])
            .await
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn get_tx_by_hash(
        &self,
        tx_hash: B256,
        mempool_only: Option<bool>,
    ) -> Result<Option<reth_rpc_types::Transaction>, Error> {
        self.client
            .request(
                "eth_getTransactionByHash",
                rpc_params![tx_hash, mempool_only],
            )
            .await
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GetSoftConfirmationResponse {
    pub l2_height: u64,
    #[serde(with = "hex::serde")]
    pub hash: SoftConfirmationHash,
    #[serde(with = "hex::serde")]
    pub prev_hash: SoftConfirmationHash,
    pub da_slot_height: u64,
    #[serde(with = "hex::serde")]
    pub da_slot_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    pub da_slot_txs_commitment: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<HexTx>>,
    #[serde(with = "hex::serde")]
    pub state_root: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub soft_confirmation_signature: Vec<u8>,
    pub deposit_data: Vec<HexTx>, // Vec<u8> wrapper around deposit data
    #[serde(with = "hex::serde")]
    pub pub_key: Vec<u8>,
    pub l1_fee_rate: u128,
    pub timestamp: u64,
}

impl From<GetSoftConfirmationResponse> for SignedSoftConfirmation {
    fn from(val: GetSoftConfirmationResponse) -> Self {
        SignedSoftConfirmation::new(
            val.l2_height,
            val.hash,
            val.prev_hash,
            val.da_slot_height,
            val.da_slot_hash,
            val.da_slot_txs_commitment,
            val.l1_fee_rate,
            val.txs
                .unwrap_or_default()
                .into_iter()
                .map(|tx| tx.tx)
                .collect(),
            val.deposit_data.into_iter().map(|tx| tx.tx).collect(),
            val.soft_confirmation_signature,
            val.pub_key,
            val.timestamp,
        )
    }
}
