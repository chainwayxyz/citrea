use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::block::{L2Block, L2Header, SignedL2Header};
use sov_rollup_interface::rpc::block::{L2BlockResponse, L2HeaderResponse};
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::StorageRootHash;

use super::DbHash;

/// The on-disk format for a L2 block. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredL2Block {
    /// The l2 height of the l2 block
    pub height: u64,
    /// The hash of the batch
    pub hash: DbHash,
    /// The hash of the previous batch
    pub prev_hash: DbHash,
    /// The transactions which occurred in this batch.
    pub txs: Vec<StoredTransaction>,
    /// State root
    pub state_root: StorageRootHash,
    /// Sequencer signature
    pub signature: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp
    pub timestamp: u64,
    /// Transactions merkle root
    pub tx_merkle_root: [u8; 32],
}

impl TryFrom<StoredL2Block> for L2Block {
    type Error = borsh::io::Error;

    fn try_from(val: StoredL2Block) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .map(|tx| {
                let body = tx.body.as_ref().unwrap();
                borsh::from_slice::<Transaction>(body)
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
        let signed_header = SignedL2Header::new(header, val.hash, val.signature);

        let res = L2Block::new(signed_header, parsed_txs);
        Ok(res)
    }
}

impl TryFrom<StoredL2Block> for L2BlockResponse {
    type Error = anyhow::Error;

    fn try_from(value: StoredL2Block) -> Result<Self, Self::Error> {
        let header = L2HeaderResponse {
            height: value.height,
            hash: value.hash,
            prev_hash: value.prev_hash,
            state_root: value.state_root,
            signature: value.signature,
            l1_fee_rate: value.l1_fee_rate,
            timestamp: value.timestamp,
            tx_merkle_root: value.tx_merkle_root,
        };
        Ok(Self {
            header,
            txs: Some(
                value
                    .txs
                    .into_iter()
                    .filter_map(|tx| tx.body.map(Into::into))
                    .collect(),
            ), // Rollup full nodes don't store tx bodies
        })
    }
}

/// The on-disk format of a transaction. Includes the txhash, the serialized tx data,
/// and identifies the events emitted by this transaction
#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize, Clone)]
pub struct StoredTransaction {
    /// The hash of the transaction.
    pub hash: DbHash,
    /// The serialized transaction data, if the rollup decides to store it.
    pub body: Option<Vec<u8>>,
}
