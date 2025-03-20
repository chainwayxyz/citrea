//! Common types shared between state and modules

mod address;
mod bytes;
mod error;

pub use address::*;
pub use bytes::*;
pub use error::*;
#[cfg(feature = "std")]
pub use jmt::Version;

/// The version of the JellyfishMerkleTree state.
#[cfg(not(feature = "std"))]
pub type Version = u64;
