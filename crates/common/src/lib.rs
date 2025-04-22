//! Common crate provides helper methods that is shared across the workspace
#![forbid(unsafe_code)]

pub mod backup;
pub mod cache;
pub mod config;
pub mod da;
pub mod db_migrations;
pub mod error;
pub mod l2;
pub mod rpc;
pub mod utils;

pub use config::*;
use sov_rollup_interface::zk::StorageRootHash;

type L2BlockHash = [u8; 32];

pub struct InitParams {
    /// The last known state root
    pub prev_state_root: StorageRootHash,
    /// The last known batch hash
    pub prev_l2_block_hash: L2BlockHash,
}
