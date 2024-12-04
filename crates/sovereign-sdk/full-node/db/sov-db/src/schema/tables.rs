//! This module defines the following tables:
//!
//!
//! Slot Tables:
//! - `SlotNumber -> StoredSlot`
//! - `SlotNumber -> Vec<BatchNumber>`
//!
//! Batch Tables:
//! - `BatchNumber -> StoredBatch`
//! - `BatchHash -> BatchNumber`
//!
//! Tx Tables:
//! - `TxNumber -> (TxHash,Tx)`
//! - `TxHash -> TxNumber`
//!
//! Event Tables:
//! - `(EventKey, TxNumber) -> EventNumber`
//! - `EventNumber -> (EventKey, EventValue)`
//!
//! JMT Tables:
//! - `KeyHash -> Key`
//! - `(Key, Version) -> JmtValue`
//! - `NodeKey -> Node`
//!
//! Module Accessory State Table:
//! - `(ModuleAddress, Key) -> Value`

use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use jmt::storage::{NibblePath, Node, NodeKey};
use jmt::Version;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::stf::StateDiff;
use sov_schema_db::schema::{KeyDecoder, KeyEncoder, ValueCodec};
use sov_schema_db::{CodecError, SeekKeyEncoder};

use super::types::{
    AccessoryKey, AccessoryStateValue, BatchNumber, DbHash, JmtValue, L2HeightRange, SlotNumber,
    StateKey, StoredBatch, StoredBatchProof, StoredLightClientProof, StoredSlot,
    StoredSoftConfirmation, StoredVerifiedProof,
};

/// A list of all tables used by the StateDB. These tables store rollup state - meaning
/// account balances, nonces, etc.
pub const STATE_TABLES: &[&str] = &[
    KeyHashToKey::table_name(),
    JmtValues::table_name(),
    JmtNodes::table_name(),
];

/// A list of all tables used by the LedgerDB. These tables store rollup "history" - meaning
/// transaction, events, receipts, etc.
pub const LEDGER_TABLES: &[&str] = &[
    ExecutedMigrations::table_name(),
    SlotByNumber::table_name(),
    SlotByHash::table_name(),
    SoftConfirmationByNumber::table_name(),
    SoftConfirmationByHash::table_name(),
    L2RangeByL1Height::table_name(),
    L2Witness::table_name(),
    L2GenesisStateRoot::table_name(),
    LastStateDiff::table_name(),
    LightClientProofBySlotNumber::table_name(),
    PendingSequencerCommitmentL2Range::table_name(),
    LastSequencerCommitmentSent::table_name(),
    ProverLastScannedSlot::table_name(),
    BatchByNumber::table_name(),
    SoftConfirmationStatus::table_name(),
    CommitmentsByNumber::table_name(),
    ProofsBySlotNumber::table_name(),
    ProofsBySlotNumberV2::table_name(),
    VerifiedBatchProofsBySlotNumber::table_name(),
    MempoolTxs::table_name(),
    PendingProvingSessions::table_name(),
    ProverStateDiffs::table_name(),
    LastPrunedBlock::table_name(),
    #[cfg(test)]
    TestTableOld::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
];

/// A list of all tables used by the NativeDB. These tables store
/// "accessory" state only accessible from a native execution context, to be
/// used for JSON-RPC and other tooling.
pub const NATIVE_TABLES: &[&str] = &[ModuleAccessoryState::table_name()];

/// Macro to define a table that implements [`sov_schema_db::Schema`].
/// KeyCodec<Schema> and ValueCodec<Schema> must be implemented separately.
///
/// ```ignore
/// define_table_without_codec!(
///  /// A table storing keys and value
///  (MyTable) MyKey => MyValue
/// )
///
/// // This impl must be written by hand
/// impl KeyCodec<MyTable> for MyKey {
/// // ...
/// }
///
/// // This impl must be written by hand
/// impl ValueCodec<MyTable> for MyValue {
/// // ...
/// }
/// ```
macro_rules! define_table_without_codec {
    ($(#[$docs:meta])+ ( $table_name:ident ) $key:ty => $value:ty) => {
        $(#[$docs])+
        ///
        #[doc = concat!("Takes [`", stringify!($key), "`] as a key and returns [`", stringify!($value), "`]")]
        #[derive(Clone, Copy, Debug, Default)]
        pub(crate) struct $table_name;

        impl ::sov_schema_db::schema::Schema for $table_name {
            const COLUMN_FAMILY_NAME: &'static str = $table_name::table_name();
            type Key = $key;
            type Value = $value;
        }

        impl $table_name {
            #[doc=concat!("Return ", stringify!($table_name), " as it is present inside the database.")]
            pub const fn table_name() -> &'static str {
                ::core::stringify!($table_name)
            }
        }

        impl ::std::fmt::Display for $table_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::core::write!(f, "{}", stringify!($table_name))
            }
        }
    };
}

macro_rules! impl_borsh_value_codec {
    ($table_name:ident, $value:ty) => {
        impl ::sov_schema_db::schema::ValueCodec<$table_name> for $value {
            fn encode_value(
                &self,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, ::sov_schema_db::CodecError> {
                ::borsh::to_vec(self).map_err(Into::into)
            }

            fn decode_value(
                data: &[u8],
            ) -> ::std::result::Result<Self, ::sov_schema_db::CodecError> {
                ::borsh::BorshDeserialize::deserialize_reader(&mut &data[..]).map_err(Into::into)
            }
        }
    };
}

/// Macro to define a table that implements [`sov_schema_db::schema::Schema`].
/// Automatically generates KeyCodec<...> and ValueCodec<...> implementations
/// using the Encode and Decode traits from sov_rollup_interface
///
/// ```ignore
/// define_table_with_default_codec!(
///  /// A table storing keys and value
///  (MyTable) MyKey => MyValue
/// )
/// ```
macro_rules! define_table_with_default_codec {
    ($(#[$docs:meta])+ ($table_name:ident) $key:ty => $value:ty) => {
        define_table_without_codec!($(#[$docs])+ ( $table_name ) $key => $value);

        impl ::sov_schema_db::schema::KeyEncoder<$table_name> for $key {
            fn encode_key(&self) -> ::std::result::Result<::std::vec::Vec<u8>, ::sov_schema_db::CodecError> {
                ::borsh::to_vec(self).map_err(Into::into)
            }
        }

        impl ::sov_schema_db::schema::KeyDecoder<$table_name> for $key {
            fn decode_key(data: &[u8]) -> ::std::result::Result<Self, ::sov_schema_db::CodecError> {
                ::borsh::BorshDeserialize::deserialize_reader(&mut &data[..]).map_err(Into::into)
            }
        }

        impl_borsh_value_codec!($table_name, $value);
    };
}

/// Macro similar to [`define_table_with_default_codec`], but to be used when
/// your key type should be [`SeekKeyEncoder`]. Borsh serializes integers as
/// little-endian, but RocksDB uses lexicographic ordering which is only
/// compatible with big-endian, so we use [`bincode`] with the big-endian option
/// here.
macro_rules! define_table_with_seek_key_codec {
    ($(#[$docs:meta])+ ($table_name:ident) $key:ty => $value:ty) => {
        define_table_without_codec!($(#[$docs])+ ( $table_name ) $key => $value);

        impl ::sov_schema_db::schema::KeyEncoder<$table_name> for $key {
            fn encode_key(&self) -> ::std::result::Result<::std::vec::Vec<u8>, ::sov_schema_db::CodecError> {
                use ::anyhow::Context as _;
                use ::bincode::Options as _;

                let bincode_options = ::bincode::options()
                    .with_fixint_encoding()
                    .with_big_endian();

                bincode_options.serialize(self).context("Failed to serialize key").map_err(Into::into)
            }
        }

        impl ::sov_schema_db::schema::KeyDecoder<$table_name> for $key {
            fn decode_key(data: &[u8]) -> ::std::result::Result<Self, ::sov_schema_db::CodecError> {
                use ::anyhow::Context as _;
                use ::bincode::Options as _;

                let bincode_options = ::bincode::options()
                    .with_fixint_encoding()
                    .with_big_endian();

                bincode_options.deserialize_from(&mut &data[..]).context("Failed to deserialize key").map_err(Into::into)
            }
        }

        impl ::sov_schema_db::SeekKeyEncoder<$table_name> for $key {
            fn encode_seek_key(&self) -> ::std::result::Result<::std::vec::Vec<u8>, ::sov_schema_db::CodecError> {
                <Self as ::sov_schema_db::schema::KeyEncoder<$table_name>>::encode_key(self)
            }
        }

        impl_borsh_value_codec!($table_name, $value);
    };
}

define_table_with_seek_key_codec!(
    /// The executed DB migrations
    (ExecutedMigrations) (String, u64) => ()
);

define_table_with_seek_key_codec!(
    /// The State diff storage
    (LastStateDiff) () => StateDiff
);

define_table_with_seek_key_codec!(
    /// The primary source for slot data
    (SlotByNumber) SlotNumber => StoredSlot
);

define_table_with_default_codec!(
    /// A "secondary index" for slot data by hash
    (SlotByHash) DbHash => SlotNumber
);

define_table_with_default_codec!(
    /// The primary source for sequencer commitment data
    (CommitmentsByNumber) SlotNumber => Vec<SequencerCommitment>
);

define_table_with_seek_key_codec!(
    /// The primary source for soft confirmation data
    (SoftConfirmationByNumber) BatchNumber => StoredSoftConfirmation
);

define_table_with_default_codec!(
    /// A "secondary index" for soft confirmation data by hash
    (SoftConfirmationByHash) DbHash => BatchNumber
);

define_table_with_default_codec!(
    /// The primary source of reverse look-up L2 height ranges for L1 heights
    (L2RangeByL1Height) SlotNumber => L2HeightRange
);

define_table_with_default_codec!(
    /// The primary source of state & offchain witnesses by L2 height
    (L2Witness) BatchNumber => (Vec<u8>, Vec<u8>)
);

define_table_with_default_codec!(
    /// The primary source of genesis state root
    (L2GenesisStateRoot) () => Vec<u8>
);

define_table_with_default_codec!(
    /// The primary source for in progress sequencer commitments
    (PendingSequencerCommitmentL2Range) L2HeightRange => ()
);

define_table_with_seek_key_codec!(
    /// Sequencer uses this table to store the last commitment it sent
    (LastSequencerCommitmentSent) () => BatchNumber
);

define_table_with_seek_key_codec!(
    /// Prover uses this table to store the last slot it scanned
    /// Full node also uses this table to store the last slot it scanned
    /// However, we don't rename here to avoid breaking changes on deployed nodes
    /// and prover.
    (ProverLastScannedSlot) () => SlotNumber
);

define_table_with_seek_key_codec!(
    /// The primary source for batch data
    (BatchByNumber) BatchNumber => StoredBatch
);

define_table_with_default_codec!(
    /// Check whether a block is finalized
    (SoftConfirmationStatus) BatchNumber => sov_rollup_interface::rpc::SoftConfirmationStatus
);

define_table_without_codec!(
    /// The source of truth for JMT nodes
    (JmtNodes) NodeKey => Node
);

define_table_with_default_codec!(
    /// Light client proof data by l1 height
    (LightClientProofBySlotNumber) SlotNumber => StoredLightClientProof
);

define_table_with_default_codec!(
    /// Old version of ProofsBySlotNumber
    (ProofsBySlotNumber) SlotNumber => Vec<StoredBatchProof>
);

define_table_with_default_codec!(
    /// Proof data on L1 slot
    (ProofsBySlotNumberV2) SlotNumber => Vec<StoredBatchProof>
);

define_table_with_default_codec!(
    /// Proof data on L1 slot verified by full node
    (VerifiedBatchProofsBySlotNumber) SlotNumber => Vec<StoredVerifiedProof>
);

define_table_with_seek_key_codec!(
    /// Proving service uses this table to store pending proving sessions
    /// If a session id is completed, remove it
    (PendingProvingSessions) Vec<u8> => ()
);

define_table_with_default_codec!(
    /// Transactions in mempool (TxHash, TxData)
    (MempoolTxs) Vec<u8> => Vec<u8>
);

define_table_with_default_codec!(
    /// L2 height to state diff for prover
    (ProverStateDiffs) BatchNumber => StateDiff
);

define_table_with_seek_key_codec!(
    /// Stores the last pruned L2 block number
    (LastPrunedBlock) () => u64
);

#[cfg(test)]
define_table_with_seek_key_codec!(
    /// Test table old
    (TestTableOld) () => Vec<u64>
);

#[cfg(test)]
define_table_with_seek_key_codec!(
    /// Test table new
    (TestTableNew) u64 => (u64, u64)
);

impl KeyEncoder<JmtNodes> for NodeKey {
    fn encode_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        // 8 bytes for version, 4 each for the num_nibbles and bytes.len() fields, plus 1 byte per byte of nibllepath
        let mut output =
            Vec::with_capacity(8 + 4 + 4 + ((self.nibble_path().num_nibbles() + 1) / 2));
        let version = self.version().to_be_bytes();
        output.extend_from_slice(&version);
        BorshSerialize::serialize(self.nibble_path(), &mut output)?;
        Ok(output)
    }
}
impl KeyDecoder<JmtNodes> for NodeKey {
    fn decode_key(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        if data.len() < 8 {
            return Err(CodecError::InvalidKeyLength {
                expected: 9,
                got: data.len(),
            });
        }
        let mut version = [0u8; 8];
        version.copy_from_slice(&data[..8]);
        let version = u64::from_be_bytes(version);
        let nibble_path = NibblePath::deserialize_reader(&mut &data[8..])?;
        Ok(Self::new(version, nibble_path))
    }
}

impl ValueCodec<JmtNodes> for Node {
    fn encode_value(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        borsh::to_vec(self).map_err(CodecError::from)
    }

    fn decode_value(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        Ok(BorshDeserialize::deserialize_reader(&mut &data[..])?)
    }
}

define_table_without_codec!(
    /// The source of truth for JMT values by version
    (JmtValues) (StateKey, Version) => JmtValue
);

impl<T: AsRef<[u8]> + PartialEq + core::fmt::Debug> KeyEncoder<JmtValues> for (T, Version) {
    fn encode_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        let mut out =
            Vec::with_capacity(self.0.as_ref().len() + std::mem::size_of::<Version>() + 8);
        self.0
            .as_ref()
            .serialize(&mut out)
            .map_err(CodecError::from)?;
        // Write the version in big-endian order so that sorting order is based on the most-significant bytes of the key
        out.write_u64::<BigEndian>(self.1)
            .expect("serialization to vec is infallible");
        Ok(out)
    }
}

impl<T: AsRef<[u8]> + PartialEq + core::fmt::Debug> SeekKeyEncoder<JmtValues> for (T, Version) {
    fn encode_seek_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        <(T, Version) as KeyEncoder<JmtValues>>::encode_key(self)
    }
}

impl KeyDecoder<JmtValues> for (StateKey, Version) {
    fn decode_key(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let key: Vec<u8> = BorshDeserialize::deserialize_reader(&mut cursor)?;
        let version = cursor.read_u64::<BigEndian>()?;
        Ok((key, version))
    }
}

impl ValueCodec<JmtValues> for JmtValue {
    fn encode_value(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        borsh::to_vec(self).map_err(CodecError::from)
    }

    fn decode_value(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        Ok(BorshDeserialize::deserialize_reader(&mut &data[..])?)
    }
}

define_table_with_default_codec!(
    /// A mapping from key-hashes to their preimages and latest version. Since we store raw
    /// key-value pairs instead of keyHash->value pairs,
    /// this table is required to implement the `jmt::TreeReader` trait,
    /// which requires the ability to fetch values by hash.
    (KeyHashToKey) [u8;32] => StateKey
);

define_table_without_codec!(
    /// Non-JMT state stored by a module for JSON-RPC use.
    (ModuleAccessoryState) (AccessoryKey, Version) => AccessoryStateValue
);

impl KeyEncoder<ModuleAccessoryState> for (AccessoryKey, Version) {
    fn encode_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.0.len() + std::mem::size_of::<Version>() + 8);
        self.0
            .as_slice()
            .serialize(&mut out)
            .map_err(CodecError::from)?;
        // Write the version in big-endian order so that sorting order is based on the most-significant bytes of the key
        out.write_u64::<BigEndian>(self.1)
            .expect("serialization to vec is infallible");
        Ok(out)
    }
}

impl SeekKeyEncoder<ModuleAccessoryState> for (AccessoryKey, Version) {
    fn encode_seek_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        <(Vec<u8>, u64) as KeyEncoder<ModuleAccessoryState>>::encode_key(self)
    }
}

impl KeyDecoder<ModuleAccessoryState> for (AccessoryKey, Version) {
    fn decode_key(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        let key: Vec<u8> = BorshDeserialize::deserialize_reader(&mut cursor)?;
        let version = cursor.read_u64::<BigEndian>()?;
        Ok((key, version))
    }
}

impl ValueCodec<ModuleAccessoryState> for AccessoryStateValue {
    fn encode_value(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        borsh::to_vec(self).map_err(CodecError::from)
    }

    fn decode_value(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        Ok(BorshDeserialize::deserialize_reader(&mut &data[..])?)
    }
}
