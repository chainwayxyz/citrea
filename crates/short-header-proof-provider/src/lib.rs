#[cfg(feature = "native")]
mod native;
mod zk;

use std::ops::RangeInclusive;

#[cfg(feature = "native")]
pub use native::*;
use once_cell::sync::OnceCell;
use thiserror::Error;
pub use zk::*;

#[derive(Error, Debug)]
pub enum ShortHeaderProofProviderError {
    #[error("Short header proof not found")]
    ShortHeaderProofNotFound,
}

/// Short Header Proof Provider
/// This trait is used to get the short header proof by the l1 hash
/// for full nodes and provers to verify sequencer set block info system transaction parameters
pub trait ShortHeaderProofProvider: Send + Sync {
    /// Returns short header proof by the l1 hash
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        l1_hash: [u8; 32],
        prev_l1_hash: [u8; 32],
        l1_height: u64,
        txs_commitment: [u8; 32],
        coinbase_depth: u8,
        l2_height: u64, // needed on the native implementation to track queries to the provider
    ) -> Result<bool, ShortHeaderProofProviderError>;

    /// Clears queried short header proofs
    fn clear_queried_hashes(&self);

    /// Takes the queried short header proofs
    fn take_queried_hashes(&self, l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]>;

    /// Takes the last queried header hash
    /// Consequent calls will return None
    fn take_last_queried_hash(&self) -> Option<[u8; 32]>;
}

pub static SHORT_HEADER_PROOF_PROVIDER: OnceCell<Box<dyn ShortHeaderProofProvider>> =
    OnceCell::new();
