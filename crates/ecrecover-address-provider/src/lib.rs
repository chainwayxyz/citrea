//! Ecrecover Address Provider

#[cfg(feature = "native")]
mod native;
mod zk;

use std::sync::OnceLock;

#[cfg(feature = "native")]
pub use native::*;
use thiserror::Error;
pub use zk::*;

#[derive(Error, Debug)]
pub enum EcrecoverProviderError {
    #[error("No more addresses available")]
    NoMoreAddresses,
}

/// Ecrecover Address Provider
/// This trait is used to get pre-computed addresses for signature recovery
/// Native implementation: collects addresses during execution in deterministic order
/// zk context implementation: provides pre-computed addresses
pub trait EcrecoverAddressProvider: Send + Sync {
    /// Record a recovered address in order (native only)
    fn record(&self, address: [u8; 20]);

    /// Clear all recorded addresses (native only)
    fn clear(&self);

    /// Take all recorded addresses (native only)
    fn take_addresses(&self) -> Result<Vec<[u8; 20]>, EcrecoverProviderError>;

    /// Get the next address from witness (zk only)
    fn get_next(&self) -> Result<[u8; 20], EcrecoverProviderError>;
}

pub static ECRECOVER_ADDRESS_PROVIDER: OnceLock<Box<dyn EcrecoverAddressProvider>> =
    OnceLock::new();
