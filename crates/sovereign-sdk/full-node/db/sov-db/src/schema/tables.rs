//! This module defines the following tables:
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
use jmt::storage::{NibblePath, Node, NodeKey, StaleNodeIndex};
use jmt::Version;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::zk::Proof;
use sov_schema_db::schema::{KeyDecoder, KeyEncoder, ValueCodec};
use sov_schema_db::{CodecError, SeekKeyEncoder};
use uuid::Uuid;

use super::types::batch_proof::{StoredBatchProof, StoredVerifiedProof};
use super::types::l2_block::StoredL2Block;
use super::types::light_client_proof::StoredLightClientProof;
use super::types::{
    AccessoryKey, AccessoryStateValue, BonsaiSession, DbHash, JmtValue, L1Height, L2BlockNumber,
    L2HeightAndIndex, L2HeightRange, L2HeightStatus, SlotNumber, StateKey,
};

/// A list of all tables used by the StateDB. These tables store rollup state - meaning
/// account balances, nonces, etc.
pub const STATE_TABLES: &[&str] = &[
    KeyHashToKey::table_name(),
    JmtValues::table_name(),
    // when iterating we get bigger versions first
    JmtNodes::table_name(),
    // when iterating we get smaller stale since versions first
    StaleNodes::table_name(),
];

/// A list of all tables used by Sequencer LedgerDB.
///
/// Note: Please keep the list sorted alphabetically
pub const SEQUENCER_LEDGER_TABLES: &[&str] = &[
    CommitmentsByNumber::table_name(),
    ExecutedMigrations::table_name(),
    L2BlockByHash::table_name(),
    L2BlockByNumber::table_name(),
    L2GenesisStateRoot::table_name(),
    L2RangeByL1Height::table_name(),
    LastPrunedBlock::table_name(),
    MempoolTxs::table_name(),
    SequencerCommitmentByIndex::table_name(),
    ShortHeaderProofBySlotHash::table_name(),
    StateDiffByBlockNumber::table_name(),
    // #### TESTS RELATED TABLES ####
    #[cfg(test)]
    TestTableOld::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
];

/// A list of all tables used by FullNode LedgerDB
///
/// Note: Please keep the list sorted alphabetically
pub const FULL_NODE_LEDGER_TABLES: &[&str] = &[
    CommitmentMerkleRoots::table_name(),
    CommitmentsByNumber::table_name(),
    ExecutedMigrations::table_name(),
    L2BlockByHash::table_name(),
    L2BlockByNumber::table_name(),
    L2GenesisStateRoot::table_name(),
    L2RangeByL1Height::table_name(),
    L2StatusHeights::table_name(),
    LastPrunedBlock::table_name(),
    PendingProofs::table_name(),
    PendingSequencerCommitments::table_name(),
    ProverLastScannedSlot::table_name(),
    SequencerCommitmentByIndex::table_name(),
    ShortHeaderProofBySlotHash::table_name(),
    SlotByHash::table_name(),
    VerifiedBatchProofsBySlotNumber::table_name(),
    // #### TESTS RELATED TABLES ####
    #[cfg(test)]
    TestTableOld::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
];

/// A list of all tables used by BatchProver LedgerDB
///
/// Note: Please keep the list sorted alphabetically
pub const BATCH_PROVER_LEDGER_TABLES: &[&str] = &[
    CommitmentIndicesByJobId::table_name(),
    CommitmentIndicesByL1::table_name(),
    ExecutedMigrations::table_name(),
    JobIdOfCommitment::table_name(),
    L2BlockByHash::table_name(),
    L2BlockByNumber::table_name(),
    L2GenesisStateRoot::table_name(),
    LastPrunedBlock::table_name(),
    PendingBonsaiSessionByJobId::table_name(),
    PendingL1SubmissionJobs::table_name(),
    ProofByJobId::table_name(),
    ProverLastScannedSlot::table_name(),
    ProverPendingCommitments::table_name(),
    ProverStateDiffs::table_name(),
    SequencerCommitmentByIndex::table_name(),
    ShortHeaderProofBySlotHash::table_name(),
    SlotByHash::table_name(),
    // #### TESTS RELATED TABLES ####
    #[cfg(test)]
    TestTableOld::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
];

/// A list of all tables used by LightClientProver LedgerDB
///
/// Note: Please keep the list sorted alphabetically
pub const LIGHT_CLIENT_PROVER_LEDGER_TABLES: &[&str] = &[
    // Don't know if this will be needed
    CommitmentMerkleRoots::table_name(),
    ExecutedMigrations::table_name(),
    LightClientProofBySlotNumber::table_name(),
    ProverLastScannedSlot::table_name(),
    SlotByHash::table_name(),
    PendingBonsaiSessionByJobId::table_name(),
    // #### TESTS RELATED TABLES ####
    #[cfg(test)]
    TestTableOld::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
];

/// A list of all tables used by the LedgerDB. These tables store rollup "history" - meaning
/// transaction, events, receipts, etc.
///
/// Note: Please keep the list sorted alphabetically
pub const LEDGER_TABLES: &[&str] = &[
    CommitmentIndicesByJobId::table_name(),
    CommitmentIndicesByL1::table_name(),
    CommitmentMerkleRoots::table_name(),
    CommitmentsByNumber::table_name(),
    ExecutedMigrations::table_name(),
    JobIdOfCommitment::table_name(),
    L2BlockByHash::table_name(),
    L2BlockByNumber::table_name(),
    L2GenesisStateRoot::table_name(),
    L2RangeByL1Height::table_name(),
    L2StatusHeights::table_name(),
    L2Witness::table_name(),
    LastPrunedBlock::table_name(),
    LightClientProofBySlotNumber::table_name(),
    MempoolTxs::table_name(),
    PendingBonsaiSessionByJobId::table_name(),
    PendingL1SubmissionJobs::table_name(),
    PendingProofs::table_name(),
    PendingProvingSessions::table_name(),
    PendingSequencerCommitments::table_name(),
    ProofByJobId::table_name(),
    ProofsBySlotNumber::table_name(),
    ProofsBySlotNumberV2::table_name(),
    ProverLastScannedSlot::table_name(),
    ProverPendingCommitments::table_name(),
    ProverStateDiffs::table_name(),
    SequencerCommitmentByIndex::table_name(),
    ShortHeaderProofBySlotHash::table_name(),
    SlotByHash::table_name(),
    StateDiffByBlockNumber::table_name(),
    VerifiedBatchProofsBySlotNumber::table_name(),
    #[cfg(test)]
    TestTableNew::table_name(),
    #[cfg(test)]
    TestTableOld::table_name(),
];

/// A list of all tables used by the NativeDB. These tables store
/// "accessory" state only accessible from a native execution context, to be
/// used for JSON-RPC and other tooling.
pub const NATIVE_TABLES: &[&str] = &[
    ModuleAccessoryState::table_name(),
    LastPrunedL2Height::table_name(),
];

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
        pub struct $table_name;

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
    (StateDiffByBlockNumber) L2BlockNumber => StateDiff
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
    /// The primary source for l2 block data
    (L2BlockByNumber) L2BlockNumber => StoredL2Block
);

define_table_with_seek_key_codec!(
    /// Index to sequencer commitment mapping
    (SequencerCommitmentByIndex) u32 => SequencerCommitment
);

define_table_with_default_codec!(
    /// list of commitment indices by l1 height
    (CommitmentIndicesByL1) SlotNumber => Vec<u32>
);

define_table_with_default_codec!(
    /// Proving results of the job
    (ProofByJobId) Uuid => StoredBatchProof
);

define_table_with_default_codec!(
    /// Secondary index table for quickly associating commitment idx with its proving job id
    (JobIdOfCommitment) u32 => Uuid
);

define_table_with_default_codec!(
    /// Commitment indices that are associated with the proving job
    (CommitmentIndicesByJobId) Uuid => Vec<u32>
);

define_table_with_default_codec!(
    /// Commitment indices waiting to be proven
    (ProverPendingCommitments) u32 => ()
);

define_table_with_default_codec!(
    /// Jobs waiting to be submitted to DA layer
    (PendingL1SubmissionJobs) Uuid => ()
);

define_table_with_default_codec!(
    /// Pending Bonsai proving sessions by job id
    (PendingBonsaiSessionByJobId) Uuid => BonsaiSession
);

define_table_with_default_codec!(
    /// A "secondary index" for l2 block data by hash
    (L2BlockByHash) DbHash => L2BlockNumber
);

define_table_with_default_codec!(
    /// A "secondary index" for l2 block data by hash
    (ShortHeaderProofBySlotHash) DbHash => Vec<u8>
);

define_table_with_default_codec!(
    /// The primary source of reverse look-up L2 height ranges for L1 heights
    (L2RangeByL1Height) SlotNumber => L2HeightRange
);

define_table_with_default_codec!(
    /// The primary source of state & offchain witnesses by L2 height
    (L2Witness) L2BlockNumber => (Vec<u8>, Vec<u8>)
);

define_table_with_default_codec!(
    /// The primary source of genesis state root
    (L2GenesisStateRoot) () => Vec<u8>
);

define_table_with_seek_key_codec!(
    /// Prover uses this table to store the last slot it scanned
    /// Full node also uses this table to store the last slot it scanned
    /// However, we don't rename here to avoid breaking changes on deployed nodes
    /// and prover.
    (ProverLastScannedSlot) () => SlotNumber
);

define_table_without_codec!(
    /// The source of truth for JMT nodes
    (JmtNodes) NodeKey => Node
);

define_table_with_default_codec!(
    /// The list of stale nodes in JMT
    (StaleNodes) StaleNodeIndex => ()
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

define_table_with_seek_key_codec!(
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
    (ProverStateDiffs) L2BlockNumber => StateDiff
);

define_table_with_seek_key_codec!(
    /// Stores the last pruned L2 block number
    (LastPrunedBlock) () => u64
);

define_table_with_default_codec!(
    /// Stores merkle hash of seuencer commitment => l2 range
    (CommitmentMerkleRoots) [u8; 32] => L2HeightRange
);

define_table_with_seek_key_codec!(
    /// Stores L2 height and index per status
    (L2StatusHeights) (L2HeightStatus, u64) => L2HeightAndIndex
);

define_table_with_seek_key_codec!(
    /// Out of order sequencer commitments
    (PendingSequencerCommitments) u32 => (SequencerCommitment, L1Height)
);

define_table_with_seek_key_codec!(
    /// Out of order proofs
    (PendingProofs) (u32, u32) => (Proof, L1Height)
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
        // 8 bytes for version, 4 each for the num_nibbles and bytes.len() fields, plus 1 byte per byte of nibblepath
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

impl<T: AsRef<[u8]> + core::fmt::Debug> KeyEncoder<JmtValues> for (T, Version) {
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

impl SeekKeyEncoder<JmtNodes> for NodeKey {
    fn encode_seek_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        self.encode_key()
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> SeekKeyEncoder<JmtValues> for (T, Version) {
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

define_table_without_codec!(
    /// last pruned l2 height
    (LastPrunedL2Height) () => u64
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

impl KeyEncoder<LastPrunedL2Height> for () {
    fn encode_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl SeekKeyEncoder<ModuleAccessoryState> for (AccessoryKey, Version) {
    fn encode_seek_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        <(Vec<u8>, u64) as KeyEncoder<ModuleAccessoryState>>::encode_key(self)
    }
}

impl SeekKeyEncoder<LastPrunedL2Height> for () {
    fn encode_seek_key(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        <() as KeyEncoder<LastPrunedL2Height>>::encode_key(self)
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

impl KeyDecoder<LastPrunedL2Height> for () {
    fn decode_key(_data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        Ok(())
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
impl ValueCodec<LastPrunedL2Height> for u64 {
    fn encode_value(&self) -> sov_schema_db::schema::Result<Vec<u8>> {
        borsh::to_vec(self).map_err(CodecError::from)
    }

    fn decode_value(data: &[u8]) -> sov_schema_db::schema::Result<Self> {
        Ok(BorshDeserialize::deserialize_reader(&mut &data[..])?)
    }
}

#[cfg(test)]
mod tests {
    use sov_schema_db::test::{TestCompositeField, TestField};
    use sov_schema_db::{define_schema, Schema, SchemaBatch, DB};

    define_schema!(
        TestSchemaDefaultCodec,
        TestCompositeField,
        TestField,
        "TestDefault"
    );
    define_schema!(
        TestSchemaSeekKeyCodec,
        TestCompositeField,
        TestField,
        "TestSeekKey"
    );

    // Define tables using both codecs for comparison
    define_table_with_default_codec!(
        /// Test table with default codec (little endian)
        (TestTableDefault) (u32, u32) => u32
    );

    define_table_with_seek_key_codec!(
        /// Test table with seek key codec (big endian)
        (TestTableSeekKey) (u32, u32) => u32
    );

    #[test]
    fn test_codec_ordering_comparison() {
        let test_values: Vec<((u32, u32), u32)> = (0..8)
            .map(|i| {
                let val = 1u32 << (i * 4);
                ((val, val + 1), val)
            })
            .collect();

        // Test default codec
        let default_ordering = {
            let db = DB::open_temp("test-default", vec![TestTableDefault::COLUMN_FAMILY_NAME]);
            let mut batch = SchemaBatch::new();
            for (key, value) in &test_values {
                batch.put::<TestTableDefault>(key, value).unwrap();
            }
            db.write_schemas(batch).unwrap();

            let mut iter = db.iter::<TestTableDefault>().unwrap();
            iter.seek_to_first();
            iter.map(|item| item.unwrap().key.0).collect::<Vec<_>>()
        };

        // Test seek key codec
        let seekkey_ordering = {
            let db = DB::open_temp("test-seekkey", vec![TestTableSeekKey::COLUMN_FAMILY_NAME]);
            let mut batch = SchemaBatch::new();
            for (key, value) in &test_values {
                batch.put::<TestTableSeekKey>(key, value).unwrap();
            }
            db.write_schemas(batch).unwrap();

            let mut iter = db.iter::<TestTableSeekKey>().unwrap();
            iter.seek_to_first();
            iter.map(|item| item.unwrap().key.0).collect::<Vec<_>>()
        };

        // Verify seek key codec maintains ordering
        let mut expected = seekkey_ordering.clone();
        expected.sort();
        assert_eq!(seekkey_ordering, expected);

        // Verify default codec produces incorrect ordering
        assert_ne!(default_ordering, seekkey_ordering);
    }
}
