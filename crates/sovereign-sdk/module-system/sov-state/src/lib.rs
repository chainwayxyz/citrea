//! Storage and state management interfaces for Sovereign SDK modules.

#![deny(missing_docs)]

pub mod codec;

#[cfg(feature = "native")]
mod prover_storage;

mod witness;
mod zk_storage;

#[cfg(feature = "native")]
pub use prover_storage::ProverStorage;
pub use zk_storage::ZkStorage;

pub mod config;

pub use sov_modules_core::{
    storage, AlignedVec, CacheLog, OrderedReadsAndWrites, Prefix, Storage, StorageInternalCache,
    Witness,
};

pub use crate::witness::ArrayWitness;

/// The default Witness type used in merkle proofs for storage access, typically found as a type parameter for [`ProverStorage`].
pub type DefaultWitness = ArrayWitness;
/// The default Hasher type used in merkle proofs for storage access, typically found as a type parameter for [`ProverStorage`].
pub type DefaultHasher = sha2::Sha256;
