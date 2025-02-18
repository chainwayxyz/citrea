#[cfg(feature = "native")]
mod native;
mod zk;

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
    ) -> Result<bool, ShortHeaderProofProviderError>;
}

pub static SHORT_HEADER_PROOF_PROVIDER: OnceCell<Box<dyn ShortHeaderProofProvider>> =
    OnceCell::new();
