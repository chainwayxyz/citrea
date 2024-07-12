mod helpers;
#[cfg(feature = "native")]
mod rpc;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;
pub mod verifier;

#[cfg(feature = "native")]
const REVEAL_OUTPUT_AMOUNT: u64 = 546;
