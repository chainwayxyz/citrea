//! Cryptographic primitives for the Sovereign SDK.

use std::fmt::Debug;
use std::hash::Hash;

use default_signature::SigVerificationError;

pub mod default_signature;
pub mod error;
mod pub_key_hex;
mod serde_pub_key;

use error::KeyError;
pub use pub_key_hex::PublicKeyHex;

pub trait Signature:
    borsh::BorshDeserialize
    + borsh::BorshSerialize
    + for<'a> TryFrom<&'a [u8], Error = KeyError>
    + Eq
    + Clone
    + std::fmt::Debug
    + Send
    + Sync
{
    /// The public key associated with the key pair of the signature.
    type PublicKey;

    /// Verifies the signature.
    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError>;
}

/// PublicKey used in the Module System.
pub trait PublicKey:
    borsh::BorshDeserialize
    + borsh::BorshSerialize
    + for<'a> TryFrom<&'a [u8], Error = KeyError>
    + Eq
    + Hash
    + Clone
    + Debug
    + Send
    + Sync
    + serde::Serialize
    + for<'a> serde::Deserialize<'a>
{
    /// Returns a representation of the public key that can be represented as a rollup address.
    fn to_address<A: From<[u8; 32]>>(&self) -> A;
}

/// A PrivateKey used in the Module System.
#[cfg(feature = "native")]
pub trait PrivateKey: Debug + Send + Sync + for<'a> TryFrom<&'a [u8], Error = KeyError> {
    /// The public key associated with the key pair.
    type PublicKey: PublicKey;

    /// The signature associated with the key pair.
    type Signature: Signature<PublicKey = Self::PublicKey>;

    /// Generates a new key pair, using a static entropy.
    fn generate() -> Self;

    /// Returns the public key associated with this private key.
    fn pub_key(&self) -> Self::PublicKey;

    /// Sign the provided message.
    fn sign(&self, msg: &[u8]) -> Self::Signature;

    /// Returns a representation of the public key that can be represented as a rollup address.
    fn to_address<A: From<[u8; 32]>>(&self) -> A {
        self.pub_key().to_address::<A>()
    }
}
