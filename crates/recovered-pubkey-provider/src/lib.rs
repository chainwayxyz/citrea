//! Ecrecover Address Provider
#[cfg(not(feature = "native"))]
use std::sync::OnceLock;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EcrecoverProviderError {
    #[error("No more pubkeys available")]
    NoMorePubkeys,
    #[error("Recovered pubkey collection is already active on this thread")]
    CollectionAlreadyActive,
    #[error("Recovered pubkey collection is not active on this thread")]
    CollectionNotActive,
}

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{RecoveredPubkeyCollectionGuard, RecoveredPubkeyProvider};

#[cfg(not(feature = "native"))]
mod zk;
#[cfg(not(feature = "native"))]
pub use zk::RecoveredPubkeyProvider;

pub type Secp256k1Pubkey = [u8; 65];

#[cfg(feature = "native")]
pub static RECOVERED_PUBKEY_PROVIDER: RecoveredPubkeyProvider = RecoveredPubkeyProvider::new();

#[cfg(not(feature = "native"))]
pub static RECOVERED_PUBKEY_PROVIDER: OnceLock<RecoveredPubkeyProvider> = OnceLock::new();
