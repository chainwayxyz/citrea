pub mod helpers;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;

#[cfg(feature = "native")]
pub mod monitoring;

#[cfg(feature = "native")]
pub mod error;
#[cfg(feature = "native")]
pub mod fee;

#[cfg(feature = "native")]
pub mod rpc;

#[cfg(feature = "testing")]
pub mod test_utils;

pub mod network_constants;

pub mod verifier;

#[cfg(feature = "native")]
/// The minimal non-dust value output in reveal txs.
pub const REVEAL_OUTPUT_AMOUNT: u64 = 546;

#[cfg(feature = "native")]
/// This is added to reveal output in order to bruteforce nonces for wtxid prefixes.
const REVEAL_OUTPUT_THRESHOLD: u64 = 2000;
