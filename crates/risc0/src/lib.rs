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
