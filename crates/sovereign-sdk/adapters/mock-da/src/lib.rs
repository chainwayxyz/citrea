#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "native")]
mod db_connector;
#[cfg(feature = "native")]
mod service;
mod types;
/// Contains DaSpec and DaVerifier
pub mod verifier;

#[cfg(feature = "native")]
pub use service::*;
pub use types::*;
pub use verifier::MockDaSpec;
