//! This crate defines the core traits and types used by all Sovereign SDK rollups.
//! It specifies the interfaces which allow the same "business logic" to run on different
//! DA layers and be proven with different zkVMS, all while retaining compatibility
//! with the same basic full node implementation.

#![deny(missing_docs)]

/// The current version of Citrea.
///
/// Mostly used for web3_clientVersion RPC calls and might be used for other purposes.
#[cfg(feature = "native")]
pub const CITREA_VERSION: &str = "v0.6.7";

/// Fork module
pub mod fork;
pub mod mmr;
mod network;
mod node;
/// Specs module
pub mod spec;
mod state_machine;

#[cfg(not(feature = "native"))]
pub use std::rc::Rc as RefCount;
#[cfg(feature = "native")]
pub use std::sync::Arc as RefCount;

pub use network::*;
pub use node::*;
pub use state_machine::*;
pub use {anyhow, digest};
