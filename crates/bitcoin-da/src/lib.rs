pub mod helpers;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;
pub mod verifier;

#[cfg(feature = "native")]
pub const REVEAL_OUTPUT_AMOUNT: u64 = 546;

#[cfg(feature = "native")]
const REVEAL_OUTPUT_THRESHOLD: u64 = 2000;
