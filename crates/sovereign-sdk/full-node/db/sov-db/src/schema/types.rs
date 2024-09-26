use std::marker::PhantomData;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::{
    HexTx, ProofResponse, ProofRpcResponse, SoftConfirmationResponse, StateTransitionRpcResponse,
    TxIdentifier, TxResponse, VerifiedProofResponse,
};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::stf::{Event, EventKey, TransactionReceipt};
use sov_rollup_interface::zk::{CumulativeStateDiff, Proof};

/// A cheaply cloneable bytes abstraction for use within the trust boundary of the node
/// (i.e. when interfacing with the database). Serializes and deserializes more efficiently,
/// than most bytes abstractions, but is vulnerable to out-of-memory attacks
/// when read from an untrusted source.
///
/// # Warning
/// Do not use this type when deserializing data from an untrusted source!!
#[derive(
    Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Default, BorshDeserialize, BorshSerialize,
)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct DbBytes(Arc<Vec<u8>>);

impl DbBytes {
    /// Create `DbBytes` from a `Vec<u8>`
    pub fn new(contents: Vec<u8>) -> Self {
        Self(Arc::new(contents))
    }
}

impl From<Vec<u8>> for DbBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::new(value))
    }
}

impl AsRef<[u8]> for DbBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// The "key" half of a key/value pair from accessory state.
///
/// See [`NativeDB`](crate::native_db::NativeDB) for more information.
pub type AccessoryKey = Vec<u8>;
/// The "value" half of a key/value pair from accessory state.
///
/// See [`NativeDB`](crate::native_db::NativeDB) for more information.
pub type AccessoryStateValue = Option<Vec<u8>>;

/// A hash stored in the database
pub type DbHash = [u8; 32];
/// The "value" half of a key/value pair from the JMT
pub type JmtValue = Option<Vec<u8>>;
pub(crate) type StateKey = Vec<u8>;

/// The on-disk format of a slot. Specifies the batches contained in the slot
/// and the hash of the da block. TODO(@preston-evans98): add any additional data
/// required to reconstruct the da block proof.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct StoredSlot {
    /// The slot's hash, as reported by the DA layer.
    pub hash: DbHash,
    /// Any extra data which the rollup decides to store relating to this slot.
    pub extra_data: DbBytes,
    /// The range of batches which occurred in this slot.
    pub batches: std::ops::Range<BatchNumber>,
}

/// The on-disk format for a proof. Stores the tx id of the proof sent to da, proof data and state transition
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredProof {
    /// Tx id
    pub l1_tx_id: [u8; 32],
    /// Proof
    pub proof: Proof,
    /// State transition
    pub state_transition: StoredStateTransition,
}

impl From<StoredProof> for ProofResponse {
    fn from(value: StoredProof) -> Self {
        Self {
            l1_tx_id: value.l1_tx_id,
            proof: convert_to_rpc_proof(value.proof),
            state_transition: StateTransitionRpcResponse::from(value.state_transition),
        }
    }
}

/// The on-disk format for a proof verified by full node. Stores proof data and state transition
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredVerifiedProof {
    /// Verified Proof
    pub proof: Proof,
    /// State transition
    pub state_transition: StoredStateTransition,
}

impl From<StoredVerifiedProof> for VerifiedProofResponse {
    fn from(value: StoredVerifiedProof) -> Self {
        Self {
            proof: convert_to_rpc_proof(value.proof),
            state_transition: StateTransitionRpcResponse::from(value.state_transition),
        }
    }
}

/// The on-disk format for a state transition.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
pub struct StoredStateTransition {
    /// The state of the rollup before the transition
    pub initial_state_root: Vec<u8>,
    /// The state of the rollup after the transition
    pub final_state_root: Vec<u8>,
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    pub da_slot_hash: [u8; 32],
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    pub sequencer_da_public_key: Vec<u8>,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
    /// An additional validity condition for the state transition which needs
    /// to be checked outside of the zkVM circuit. This typically corresponds to
    /// some claim about the DA layer history, such as (X) is a valid block on the DA layer
    pub validity_condition: Vec<u8>,
}

impl From<StoredStateTransition> for StateTransitionRpcResponse {
    fn from(value: StoredStateTransition) -> Self {
        Self {
            initial_state_root: value.initial_state_root,
            final_state_root: value.final_state_root,
            state_diff: value.state_diff,
            da_slot_hash: value.da_slot_hash,
            sequencer_da_public_key: value.sequencer_da_public_key,
            sequencer_public_key: value.sequencer_public_key,
            validity_condition: value.validity_condition,
            sequencer_commitments_range: value.sequencer_commitments_range,
            preproven_commitments: value.preproven_commitments,
        }
    }
}

/// Converts proof data to hex encoded rpc response
pub fn convert_to_rpc_proof(stored_proof: Proof) -> ProofRpcResponse {
    match stored_proof {
        Proof::Full(data) => ProofRpcResponse::Full(data),
        Proof::PublicInput(data) => ProofRpcResponse::PublicInput(data),
    }
}

/// The on-disk format for a batch. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
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

impl From<StoredSoftConfirmation> for SignedSoftConfirmation {
    fn from(value: StoredSoftConfirmation) -> Self {
        SignedSoftConfirmation::new(
            value.l2_height,
            value.hash,
            value.prev_hash,
            value.da_slot_height,
            value.da_slot_hash,
            value.da_slot_txs_commitment,
            value.l1_fee_rate,
            value.txs.into_iter().map(|tx| tx.body.unwrap()).collect(),
            value.deposit_data,
            value.soft_confirmation_signature,
            value.pub_key,
            value.timestamp,
        )
    }
}

/// The range of L2 heights (soft confirmations) for a given L1 block
/// (start, end) inclusive
pub type L2HeightRange = (BatchNumber, BatchNumber);

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

/// The on-disk format for a batch. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct StoredBatch {
    /// The hash of the batch, as reported by the DA layer.
    pub hash: DbHash,
    /// The range of transactions which occurred in this batch.
    pub txs: std::ops::Range<TxNumber>,
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

impl<R: DeserializeOwned> TryFrom<StoredTransaction> for TxResponse<R> {
    type Error = anyhow::Error;
    fn try_from(value: StoredTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: value.hash,
            body: value.body.map(HexTx::from),
            phantom_data: PhantomData,
        })
    }
}

/// Split a `TransactionReceipt` into a `StoredTransaction` and a list of `Event`s for storage in the database.
pub fn split_tx_for_storage<R: Serialize>(
    tx: TransactionReceipt<R>,
) -> (StoredTransaction, Vec<Event>) {
    let tx_for_storage = StoredTransaction {
        hash: tx.tx_hash,
        body: tx.body_to_save,
    };
    (tx_for_storage, tx.events)
}

/// An identifier that specifies a single event
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum EventIdentifier {
    /// A unique identifier for an event consisting of a [`TxIdentifier`] and an offset into that transaction's event list
    TxIdAndIndex((TxIdentifier, u64)),
    /// A unique identifier for an event consisting of a [`TxIdentifier`] and an event key
    TxIdAndKey((TxIdentifier, EventKey)),
    /// The monotonically increasing number of the event, ordered by the DA layer For example, if the first tx
    /// contains 7 events, tx 2 contains 11 events, and tx 3 contains 7 txs,
    /// the last event in tx 3 would have number 25. The counter never resets.
    Number(EventNumber),
}

/// An identifier for a group of related events
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum EventGroupIdentifier {
    /// All of the events which occurred in a particular transaction
    TxId(TxIdentifier),
    /// All events which a particular key
    /// (typically, these events will have been emitted by several different transactions)
    Key(Vec<u8>),
}

macro_rules! u64_wrapper {
    ($name:ident) => {
        /// A typed wrapper around u64 implementing `Encode` and `Decode`
        #[derive(
            Clone,
            Copy,
            ::core::fmt::Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            ::borsh::BorshDeserialize,
            ::borsh::BorshSerialize,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        #[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
        pub struct $name(pub u64);

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        #[cfg(feature = "arbitrary")]
        impl<'a> ::arbitrary::Arbitrary<'a> for $name {
            fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
                u.arbitrary().map($name)
            }
        }
    };
}

u64_wrapper!(SlotNumber);
u64_wrapper!(BatchNumber);
u64_wrapper!(TxNumber);
u64_wrapper!(EventNumber);

#[cfg(feature = "arbitrary")]
pub mod arbitrary {
    //! Arbitrary definitions for the types.

    use super::*;

    impl<'a> ::arbitrary::Arbitrary<'a> for DbBytes {
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            u.arbitrary().map(DbBytes::new)
        }
    }

    impl<'a> ::arbitrary::Arbitrary<'a> for StoredTransaction {
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            Ok(StoredTransaction {
                hash: u.arbitrary()?,
                body: u.arbitrary()?,
            })
        }
    }

    impl<'a> ::arbitrary::Arbitrary<'a> for StoredBatch {
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            Ok(StoredBatch {
                hash: u.arbitrary()?,
                txs: u.arbitrary()?,
            })
        }
    }

    impl<'a> ::arbitrary::Arbitrary<'a> for StoredSlot {
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            Ok(StoredSlot {
                hash: u.arbitrary()?,
                extra_data: u.arbitrary()?,
                batches: u.arbitrary()?,
            })
        }
    }
}
