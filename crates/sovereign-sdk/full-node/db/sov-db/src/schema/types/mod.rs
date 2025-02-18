/// Batch proof related storage types
pub mod batch_proof;
/// Light client proof related storage types
pub mod light_client_proof;
/// Soft confirmation related storage types
pub mod soft_confirmation;

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

/// The range of L2 heights (soft confirmations) for a given L1 block
/// (start, end) inclusive
pub type L2HeightRange = (SoftConfirmationNumber, SoftConfirmationNumber);

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
u64_wrapper!(SoftConfirmationNumber);
