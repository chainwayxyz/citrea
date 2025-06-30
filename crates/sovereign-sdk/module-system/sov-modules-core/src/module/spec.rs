//! Module specification definitions.

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use sov_keys::error::KeyError;
use sov_keys::{PublicKey, Signature};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::RollupAddress;

use crate::storage::Storage;
use crate::Address;

/// The `Spec` trait configures certain key primitives to be used by a by a particular instance of a rollup.
/// `Spec` is almost always implemented on a Context object; since all Modules are generic
/// over a Context, rollup developers can easily optimize their code for different environments
/// by simply swapping out the Context (and by extension, the Spec).
///
/// For example, a rollup running in a STARK-based zkVM like Risc0 might pick Sha256 or Poseidon as its preferred hasher,
/// while a rollup running in an elliptic-curve based SNARK such as `Placeholder` from the =nil; foundation might
/// prefer a Pedersen hash. By using a generic Context and Spec, a rollup developer can trivially customize their
/// code for either (or both!) of these environments without touching their module implementations.
pub trait Spec: BorshDeserialize + BorshSerialize {
    /// The Address type used on the rollup. Typically calculated as the hash of a public key.
    #[cfg(all(feature = "native", feature = "std"))]
    type Address: RollupAddress
        + BorshSerialize
        + BorshDeserialize
        + Sync
        // Do we always need this, even when the module does not have a JSON
        // Schema? That feels a bit wrong.
        + ::schemars::JsonSchema
        + Into<crate::common::AddressBech32>
        + From<crate::common::AddressBech32>
        + alloc::str::FromStr<Err = anyhow::Error>;

    /// The Address type used on the rollup. Typically calculated as the hash of a public key.
    #[cfg(all(feature = "native", not(feature = "std")))]
    type Address: RollupAddress
        + BorshSerialize
        + BorshDeserialize
        + Sync
        + Into<crate::common::AddressBech32>
        + From<crate::common::AddressBech32>
        + alloc::str::FromStr<Err = anyhow::Error>;

    /// The Address type used on the rollup. Typically calculated as the hash of a public key.
    #[cfg(not(feature = "native"))]
    type Address: RollupAddress + BorshSerialize + BorshDeserialize;

    /// Authenticated state storage used by the rollup. Typically some variant of a merkle-patricia trie.
    type Storage: Storage + Send + Sync;

    /// The public key used for digital signatures
    #[cfg(feature = "native")]
    type PrivateKey: sov_keys::PrivateKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;

    /// The public key used for digital signatures
    #[cfg(all(feature = "native", feature = "std"))]
    type PublicKey: PublicKey + ::schemars::JsonSchema + alloc::str::FromStr<Err = KeyError>;

    /// The public key used for digital signatures
    #[cfg(not(all(feature = "native", feature = "std")))]
    type PublicKey: PublicKey;

    /// The digital signature scheme used by the rollup
    #[cfg(all(feature = "native", feature = "std"))]
    type Signature: Signature<PublicKey = Self::PublicKey>
        + alloc::str::FromStr<Err = KeyError>
        + serde::Serialize
        + for<'a> serde::Deserialize<'a>
        + schemars::JsonSchema;

    /// The digital signature scheme used by the rollup
    #[cfg(all(not(all(feature = "native", feature = "std")), not(feature = "serde")))]
    type Signature: Signature<PublicKey = Self::PublicKey>;

    /// The digital signature scheme used by the rollup
    #[cfg(all(not(all(feature = "native", feature = "std")), feature = "serde"))]
    type Signature: Signature<PublicKey = Self::PublicKey>
        + serde::Serialize
        + for<'a> serde::Deserialize<'a>;
}

/// A context contains information which is passed to modules during
/// transaction execution. Currently, context includes the sender of the transaction
/// as recovered from its signature.
///
/// Context objects also implement the [`Spec`] trait, which specifies the types to be used in this
/// instance of the state transition function. By making modules generic over a `Context`, developers
/// can easily update their cryptography to conform to the needs of different zk-proof systems.
pub trait Context: Spec + Clone + Debug + PartialEq + 'static {
    /// Sender of the transaction.
    fn sender(&self) -> &Address;

    /// Constructor for the Context.
    fn new(sender: Address, height: u64, active_spec: SpecId, l1_fee_rate: u128) -> Self;

    /// Returns the L2 height
    /// TODO: rename to `l2_height`
    fn slot_height(&self) -> u64;

    /// The current active spec
    fn active_spec(&self) -> SpecId;

    /// The L1 fee rate applied to the l2 block
    fn l1_fee_rate(&self) -> u128;
}
