#![allow(dead_code)] // FIXME

mod helpers;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;
pub mod verifier;

#[cfg(feature = "native")]
const REVEAL_OUTPUT_AMOUNT: u64 = 546;

#[cfg(feature = "native")]
const MAX_TXBODY_SIZE: usize = 397000;

fn round(x: f64, decimals: u32) -> f64 {
    let y = 10i32.pow(decimals) as f64;
    (x * y).round() / y
}
