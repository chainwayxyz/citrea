//! SP1 host and guest adapters for Citrea.
pub use sov_rollup_interface::zk::sp1::{ProgramVKeyHash, SP1Proof};
pub mod guest;
#[cfg(feature = "native")]
pub mod host;
#[cfg(feature = "native")]
mod succinct_network;
#[cfg(feature = "native")]
pub use succinct_network::{offered_price, prove_on_network, FIRST_OFFER_PERCENT};
#[cfg(feature = "native")]
mod utils;
