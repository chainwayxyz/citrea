/// Batch proof related storage types
pub mod batch_proof;
/// L2 block related storage types
pub mod l2_block;
/// Light client proof related storage types
pub mod light_client_proof;

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
pub(crate) type StateKeyRef<'a> = &'a [u8];

/// The range of L2 heights (l2 blocks) for a given L1 block
/// (start, end) inclusive
pub type L2HeightRange = (L2BlockNumber, L2BlockNumber);

/// Height and index of a sequencer commitment
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    PartialOrd,
    ::borsh::BorshDeserialize,
    ::borsh::BorshSerialize,
    ::serde::Serialize,
    ::serde::Deserialize,
)]
pub struct L2HeightAndIndex {
    /// L2 end height
    pub height: u64,
    /// Commitment's index
    pub commitment_index: u32,
}

/// Status of a sequencer commitment
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    ::borsh::BorshDeserialize,
    ::borsh::BorshSerialize,
    ::serde::Serialize,
    ::serde::Deserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum L2HeightStatus {
    /// Commmited sequencer commitment
    Committed = 0,
    /// Proven sequencer commitment
    Proven = 1,
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
        pub struct $name(pub u64);

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

u64_wrapper!(SlotNumber);
u64_wrapper!(L2BlockNumber);
