#![warn(clippy::missing_docs_in_private_items)]
#![warn(missing_docs)]
//! Light client prover implementation for the Citrea rollup
//!
//! This crate provides functionality for running a light client prover in the Citrea network.
//!
//! There are 3 main modules:
//!
//! 1. DA block handler: Scans the L1 for finalized blocks and generates light client proofs per L1 block.
//! 2. Light client circuit: Contains the circuit logic for generating the light client proofs.
//! 3. RPC module: Provides RPC methods to query the light client proofs and batch proof method ids.

#[cfg(feature = "native")]
pub use services::*;

pub mod circuit;
#[cfg(feature = "native")]
pub mod da_block_handler;
#[cfg(feature = "native")]
pub mod db_migrations;
#[cfg(feature = "native")]
pub mod metrics;
#[cfg(feature = "native")]
pub mod rpc;
#[cfg(feature = "native")]
pub mod runner;
#[cfg(feature = "native")]
mod services;

/// Light client prover tests
#[cfg(test)]
mod tests;
