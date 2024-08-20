#![allow(dead_code)] // FIXME

mod helpers;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;
pub mod verifier;

#[cfg(feature = "native")]
const REVEAL_OUTPUT_AMOUNT: u64 = 546;

#[cfg(feature = "native")]
const MAX_TXBODY_SIZE: usize = 390000; // TODO: make better calculation for this value
