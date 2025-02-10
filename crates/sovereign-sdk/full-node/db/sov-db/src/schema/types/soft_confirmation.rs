use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::rpc::{HexTx, SoftConfirmationResponse};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;

use super::DbHash;

/// The on-disk format for a batch. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredSoftConfirmation {
    /// The l2 height of the soft confirmation
    pub l2_height: u64,
    /// The number of the batch
    pub da_slot_height: u64,
    /// The da hash of the batch
    pub da_slot_hash: [u8; 32],
    /// The da transactions commitment of the batch
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the batch
    pub hash: DbHash,
    /// The hash of the previous batch
    pub prev_hash: DbHash,
    /// The transactions which occurred in this batch.
    pub txs: Vec<StoredTransaction>,
    /// Deposit data coming from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// State root
    pub state_root: Vec<u8>,
    /// Sequencer signature
    pub soft_confirmation_signature: Vec<u8>,
    /// Sequencer public key
    pub pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp
    pub timestamp: u64,
}

impl<'txs, Tx> TryFrom<StoredSoftConfirmation> for SignedSoftConfirmation<'txs, Tx>
where
    Tx: Clone + BorshDeserialize,
{
    type Error = borsh::io::Error;
    fn try_from(val: StoredSoftConfirmation) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .map(|tx| {
                let body = tx.body.as_ref().unwrap();
                borsh::from_slice::<Tx>(body)
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;
        let res = SignedSoftConfirmation::new(
            val.l2_height,
            val.hash,
            val.prev_hash,
            val.da_slot_height,
            val.da_slot_hash,
            val.da_slot_txs_commitment,
            val.l1_fee_rate,
            val.txs.into_iter().map(|tx| tx.body.unwrap()).collect(),
            parsed_txs.into(),
            val.deposit_data,
            val.soft_confirmation_signature,
            val.pub_key,
            val.timestamp,
        );
        Ok(res)
    }
}

impl TryFrom<StoredSoftConfirmation> for SoftConfirmationResponse {
    type Error = anyhow::Error;
    fn try_from(value: StoredSoftConfirmation) -> Result<Self, Self::Error> {
        Ok(Self {
            da_slot_hash: value.da_slot_hash,
            l2_height: value.l2_height,
            da_slot_height: value.da_slot_height,
            da_slot_txs_commitment: value.da_slot_txs_commitment,
            hash: value.hash,
            prev_hash: value.prev_hash,
            txs: Some(
                value
                    .txs
                    .into_iter()
                    .filter_map(|tx| tx.body.map(Into::into))
                    .collect(),
            ), // Rollup full nodes don't store tx bodies
            state_root: value.state_root,
            soft_confirmation_signature: value.soft_confirmation_signature,
            pub_key: value.pub_key,
            deposit_data: value
                .deposit_data
                .into_iter()
                .map(|tx_vec| HexTx { tx: tx_vec })
                .collect(),
            l1_fee_rate: value.l1_fee_rate,
            timestamp: value.timestamp,
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
