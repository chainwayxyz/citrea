//! Common crate provides helper methods that is shared across the workspace
#![forbid(unsafe_code)]

pub mod backup;
pub mod cache;
pub mod config;
pub mod da;
pub mod error;
pub mod rpc;
pub mod tasks;
pub mod utils;

pub use config::*;
use sov_rollup_interface::zk::StorageRootHash;

type SoftConfirmationHash = [u8; 32];

pub struct InitParams {
    /// The last known state root
    pub state_root: StorageRootHash,
    /// The last known batch hash
    pub batch_hash: SoftConfirmationHash,
}
