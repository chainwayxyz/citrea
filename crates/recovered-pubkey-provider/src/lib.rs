//! Ecrecover Address Provider
use std::sync::OnceLock;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EcrecoverProviderError {
    #[error("No more addresses available")]
    NoMoreAddresses,
}

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::RecoveredPubkeyProvider;

#[cfg(not(feature = "native"))]
mod zk;
#[cfg(not(feature = "native"))]
pub use zk::RecoveredPubkeyProvider;

pub type Secp256k1Pubkey = [u8; 65];

pub static RECOVERED_PUBKEY_PROVIDER: OnceLock<RecoveredPubkeyProvider> = OnceLock::new();
