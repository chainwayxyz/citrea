//! Recovered pubkey provider for the batch-proof circuit.
//!
//! Inside the circuit, transaction ecrecover is replaced by verifying a
//! pre-computed pubkey supplied as witness data. This provider hands those
//! pubkeys to the circuit in the deterministic order they are consumed.
//!
//! The pubkeys themselves are collected natively by the batch prover via
//! `citrea_evm::recover_pubkey`; this crate only provides the circuit-side
//! consumption.
use std::sync::OnceLock;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EcrecoverProviderError {
    #[error("No more pubkeys available")]
    NoMorePubkeys,
}

mod zk;
pub use zk::RecoveredPubkeyProvider;

pub type Secp256k1Pubkey = [u8; 65];

pub static RECOVERED_PUBKEY_PROVIDER: OnceLock<RecoveredPubkeyProvider> = OnceLock::new();
