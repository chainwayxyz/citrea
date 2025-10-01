#![deny(missing_docs)]
//! # RISC0 Adapter
//!
//! This crate contains an adapter allowing the Risc0 to be used as a proof system for
//! Sovereign SDK rollups.
use risc0_zkp::verify::VerificationError;
pub use risc0_zkvm::sha::Digest;
use risc0_zkvm::{InnerReceipt, PrunedValueError, Receipt};
use thiserror::Error;

pub mod guest;
#[cfg(feature = "native")]
pub mod host;

#[derive(Error, Debug)]
enum RestoreReceiptErr {
    #[error("Failed deserialize output")]
    Deserialize(#[from] bincode::Error),
    #[error("Failed to extract claim")]
    ClaimError(#[source] VerificationError),
    #[error("Claim is pruned")]
    ClaimPruned(#[source] PrunedValueError),
    #[error("Output is pruned")]
    OutputPruned(#[source] PrunedValueError),
    #[error("Output is empty")]
    OutputEmpty,
    #[error("Journal is pruned")]
    JournalPruned(#[source] PrunedValueError),
}

/// Try to restore Receipt from InnerReceipt from attached journal
fn receipt_from_inner(inner: InnerReceipt) -> Result<Receipt, RestoreReceiptErr> {
    let mb_claim = inner.claim().map_err(RestoreReceiptErr::ClaimError)?;
    let claim = mb_claim.value().map_err(RestoreReceiptErr::ClaimPruned)?;
    let output = claim
        .output
        .value()
        .map_err(RestoreReceiptErr::OutputPruned)?;
    let Some(output) = output else {
        return Err(RestoreReceiptErr::OutputEmpty)?;
    };
    let journal = output
        .journal
        .value()
        .map_err(RestoreReceiptErr::JournalPruned)?;
    Ok(Receipt::new(inner, journal))
}

/// Parse Receipt from serialized proof (based on proof format)
/// 1. Try to parse proof as InnerReceipt and restore Receipt from it
/// 2. Otherwise try to parse proof as Receipt
pub(crate) fn receipt_from_proof(serialized_proof: &[u8]) -> Result<Receipt, RestoreReceiptErr> {
    match bincode::deserialize::<InnerReceipt>(serialized_proof) {
        Ok(inner) => receipt_from_inner(inner),
        Err(e) => Err(RestoreReceiptErr::Deserialize(e)),
    }
}

/// Check if RISC0_DEV_MODE is enabled via environment variable.
///
/// This is a copy of https://github.com/risc0/risc0/blob/912c2e198f3abc1094fa55e45840febaee203c22/risc0/zkvm/src/lib.rs#L205
/// This function is deprecated in risc0, but we still need it here.
///
/// # Note
/// Be aware that this function does not check risc0 disable-dev-mode feature flag.
/// However in prover and verifier config it does the check automatically,
/// and will panic if env var is set to values below while the feature flag is set in risc0-zkvm.
///
/// # Returns
/// Returns `true` if RISC0_DEV_MODE environment variable is set to "1", "true", or "yes".
#[cfg(feature = "native")]
pub fn is_dev_mode_enabled_via_environment() -> bool {
    std::env::var("RISC0_DEV_MODE")
        .ok()
        .map(|x| x.to_lowercase())
        .filter(|x| x == "1" || x == "true" || x == "yes")
        .is_some()
}
