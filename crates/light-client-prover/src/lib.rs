#![warn(clippy::missing_docs_in_private_items)]

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
