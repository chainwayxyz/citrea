use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::HexTx;
use crate::block::{L2Block, L2Header, SignedL2Header};

/// The response to a JSON-RPC request for a particular l2 block.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct L2BlockResponse {
    /// The L2 block height.
    pub height: u64,
    /// The l2 block hash.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// The previous l2 block hash.
    #[serde(with = "hex::serde")]
    pub prev_hash: [u8; 32],
    /// The transactions in this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<HexTx>>,
    /// L2 block state root.
    #[serde(with = "hex::serde")]
    pub state_root: [u8; 32],
    /// Signature of the batch
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
    /// Public key of the signer
    #[serde(with = "hex::serde")]
    pub pub_key: Vec<u8>,
    /// Base layer fee rate sats/wei etc. per byte.
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp.
    pub timestamp: u64,
    /// Tx merkle root.
    pub tx_merkle_root: [u8; 32],
}

impl<'txs, Tx> TryFrom<L2BlockResponse> for L2Block<'txs, Tx>
where
    Tx: Clone + BorshDeserialize + BorshSerialize,
{
    type Error = borsh::io::Error;
    fn try_from(val: L2BlockResponse) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .flatten()
            .map(|tx| {
                let body = &tx.tx;
                borsh::from_slice::<Tx>(body)
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;

        let header = L2Header::new(
            val.height,
            val.prev_hash,
            val.state_root,
            val.l1_fee_rate,
            val.tx_merkle_root,
            val.timestamp,
        );
        let signed_header = SignedL2Header::new(header, val.hash, val.signature, val.pub_key);

        let res = L2Block::new(signed_header, parsed_txs.into());
        Ok(res)
    }
}
