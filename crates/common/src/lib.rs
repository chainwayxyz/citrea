//! Common crate provides helper methods that is shared across the workspace
#![forbid(unsafe_code)]

pub mod backup;
pub mod cache;
pub mod config;
pub mod da;
pub mod db_migrations;
pub mod l2;
pub mod rpc;
pub mod utils;

pub use config::*;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::zk::StorageRootHash;

type L2BlockHash = [u8; 32];

pub struct InitParams {
    /// The last known state root
    pub prev_state_root: StorageRootHash,
    /// The last known batch hash
    pub prev_l2_block_hash: L2BlockHash,
}

/// Variant to specify how to start processing L1 blocks
pub enum StartVariant { // TODO: rename to L1StartVariant
    /// Resume from the last scanned L1 block height, the following L1 block will be the next one to process.
    LastScanned(u64),
    /// Start processing from an initial L1 block height
    FromBlock(u64),
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeType {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::BatchProver => write!(f, "batch-prover"),
            NodeType::Sequencer => write!(f, "sequencer"),
            NodeType::FullNode => write!(f, "full-node"),
            NodeType::LightClientProver => write!(f, "light-client-prover"),
        }
    }
}
