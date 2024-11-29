#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

/// A 32-byte hash [`serde`]-encoded as a hex string optionally prefixed with
/// `0x`. See [`sov_rollup_interface::rpc::utils::rpc_hex`].
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HexHash(#[serde(with = "sov_rollup_interface::rpc::utils::rpc_hex")] pub [u8; 32]);
