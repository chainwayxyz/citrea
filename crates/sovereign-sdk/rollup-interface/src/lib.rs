//! This crate defines the core traits and types used by all Sovereign SDK rollups.
//! It specifies the interfaces which allow the same "business logic" to run on different
//! DA layers and be proven with different zkVMS, all while retaining compatibility
//! with the same basic full node implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// The current version of Citrea.
///
/// Mostly used for web3_clientVersion RPC calls and might be used for other purposes.
#[cfg(feature = "native")]
pub const CITREA_VERSION: &str = env!("CARGO_PKG_VERSION");

mod state_machine;
pub use state_machine::*;

mod node;

pub use node::*;
pub use {anyhow, digest};
