#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "native")]
pub mod genesis_config;
mod hooks_impl;
pub mod runtime;
/// Implements the `StateTransitionVerifier` type for checking the validity of a state transition
pub mod verifier;
