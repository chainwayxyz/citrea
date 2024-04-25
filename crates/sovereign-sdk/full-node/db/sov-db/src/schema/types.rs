use std::marker::PhantomData;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::{BatchResponse, SoftBatchResponse, TxIdentifier, TxResponse};
use sov_rollup_interface::stf::{Event, EventKey, TransactionReceipt};

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

/// The on-disk format for a batch. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredSoftBatch {
    /// The number of the batch
    pub da_slot_height: u64,
    /// The da hash of the batch
    pub da_slot_hash: [u8; 32],
    /// The da transactions commitment of the batch
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the batch
    pub hash: DbHash,
    /// The range of transactions which occurred in this batch.
    pub tx_range: std::ops::Range<TxNumber>,
    /// The transactions which occurred in this batch.
    pub txs: Vec<StoredTransaction>,
    /// Deposit data coming from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// Pre state root
    pub pre_state_root: Vec<u8>,
    /// Post state root
    pub post_state_root: Vec<u8>,
    /// Sequencer signature
    pub soft_confirmation_signature: Vec<u8>,
    /// Sequencer public key
    pub pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u64,
    /// Sequencer's block timestamp
    pub timestamp: u64,
}

/// The range of L2 heights (soft confirmations) for a given L1 block
/// (start, end) inclusive
pub type L2HeightRange = (BatchNumber, BatchNumber);

impl TryFrom<StoredSoftBatch> for SoftBatchResponse {
    type Error = anyhow::Error;
    fn try_from(value: StoredSoftBatch) -> Result<Self, Self::Error> {
        Ok(Self {
            da_slot_hash: value.da_slot_hash,
            da_slot_height: value.da_slot_height,
            da_slot_txs_commitment: value.da_slot_txs_commitment,
            hash: value.hash,
            txs: Some(
                value
                    .txs
                    .into_iter()
                    .filter_map(|tx| tx.body.map(Into::into))
                    .collect(),
            ), // Rollup full nodes don't store tx bodies
            pre_state_root: value.pre_state_root,
            post_state_root: value.post_state_root,
            soft_confirmation_signature: value.soft_confirmation_signature,
            pub_key: value.pub_key,
            deposit_data: value.deposit_data,
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

impl<B: DeserializeOwned, T> TryFrom<StoredBatch> for BatchResponse<B, T> {
    type Error = anyhow::Error;
    fn try_from(value: StoredBatch) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: value.hash,
            phantom_data: PhantomData,
            tx_range: value.txs.start.into()..value.txs.end.into(),
            txs: None,
        })
    }
}

/// The on-disk format of a transaction. Includes the txhash, the serialized tx data,
/// and identifies the events emitted by this transaction
#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize, Clone)]
pub struct StoredTransaction {
    /// The hash of the transaction.
    pub hash: DbHash,
    /// The range of event-numbers emitted by this transaction.
    pub events: std::ops::Range<EventNumber>,
    /// The serialized transaction data, if the rollup decides to store it.
    pub body: Option<Vec<u8>>,
}

impl<R: DeserializeOwned> TryFrom<StoredTransaction> for TxResponse<R> {
    type Error = anyhow::Error;
    fn try_from(value: StoredTransaction) -> Result<Self, Self::Error> {
        Ok(Self {
            hash: value.hash,
            event_range: value.events.start.into()..value.events.end.into(),
            body: value.body,
            phantom_data: PhantomData,
        })
    }
}

/// Split a `TransactionReceipt` into a `StoredTransaction` and a list of `Event`s for storage in the database.
pub fn split_tx_for_storage<R: Serialize>(
    tx: TransactionReceipt<R>,
    event_offset: u64,
) -> (StoredTransaction, Vec<Event>) {
    let event_range = EventNumber(event_offset)..EventNumber(event_offset + tx.events.len() as u64);
    let tx_for_storage = StoredTransaction {
        hash: tx.tx_hash,
        events: event_range,
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
                events: u.arbitrary()?,
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
