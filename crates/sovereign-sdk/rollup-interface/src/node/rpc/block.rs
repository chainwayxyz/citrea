use alloy_primitives::{U128, U64};
use serde::{Deserialize, Serialize};

use super::HexTx;
use crate::block::{L2Block, L2Header, SignedL2Header};
use crate::transaction::Transaction;

/// L2 Header response
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct L2HeaderResponse {
    /// The L2 block height.
    pub height: U64,
    /// The l2 block hash.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// The previous l2 block hash.
    #[serde(with = "hex::serde")]
    pub prev_hash: [u8; 32],
    /// L2 block state root.
    #[serde(with = "hex::serde")]
    pub state_root: [u8; 32],
    /// Signature of the batch
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
    /// Base layer fee rate sats/wei etc. per byte.
    pub l1_fee_rate: U128,
    /// Sequencer's block timestamp.
    pub timestamp: U64,
    /// Tx merkle root.
    pub tx_merkle_root: [u8; 32],
}

/// The response to a JSON-RPC request for a particular l2 block.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L2BlockResponse {
    /// The L2 header
    pub header: L2HeaderResponse,
    /// The transactions in this batch.
    pub txs: Vec<HexTx>,
}

impl TryFrom<L2BlockResponse> for L2Block {
    type Error = borsh::io::Error;
    fn try_from(val: L2BlockResponse) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .map(|tx| {
                let body = &tx.tx;
                borsh::from_slice::<Transaction>(body)
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        let header = L2Header::new(
            val.header.height.to(),
            val.header.prev_hash,
            val.header.state_root,
            val.header.l1_fee_rate.to(),
            val.header.tx_merkle_root,
            val.header.timestamp.to(),
        );
        let signed_header = SignedL2Header::new(header, val.header.hash, val.header.signature);

        let res = L2Block::new(signed_header, parsed_txs);
        Ok(res)
    }
}
