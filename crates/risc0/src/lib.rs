#![deny(missing_docs)]
//! # RISC0 Adapter
//!
//! This crate contains an adapter allowing the Risc0 to be used as a proof system for
//! Sovereign SDK rollups.
use risc0_zkp::verify::VerificationError;
pub use risc0_zkvm::sha::Digest;
use risc0_zkvm::{InnerReceipt, PrunedValueError, Receipt};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::zk::Matches;
use thiserror::Error;

pub mod guest;
#[cfg(feature = "native")]
pub mod host;

/// Uniquely identifies a Risc0 binary. Roughly equivalent to
/// the hash of the ELF file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Risc0MethodId([u32; 8]);

impl Risc0MethodId {
    /// Create a new `Risc0MethodId` from a slice of u32s.
    pub fn new(data: [u32; 8]) -> Self {
        Self(data)
    }

    /// Returns a reference to the `Risc0MethodId` as a slice of u32s.
    pub fn as_words(&self) -> &[u32] {
        &self.0
    }
}

impl Matches<Self> for Risc0MethodId {
    fn matches(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Matches<Digest> for Risc0MethodId {
    fn matches(&self, other: &Digest) -> bool {
        self.0 == other.as_words()
    }
}

impl Matches<[u32; 8]> for Risc0MethodId {
    fn matches(&self, other: &[u32; 8]) -> bool {
        &self.0 == other
    }
}

impl From<Risc0MethodId> for [u32; 8] {
    fn from(val: Risc0MethodId) -> Self {
        val.0
    }
}

impl From<[u32; 8]> for Risc0MethodId {
    fn from(value: [u32; 8]) -> Self {
        Risc0MethodId(value)
    }
}

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
