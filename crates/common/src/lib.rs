//! Common crate provides helper methods that is shared across the workspace
#![forbid(unsafe_code)]

pub mod backup;
pub mod cache;
pub mod config;
pub mod da;
pub mod l2;
pub mod rpc;
pub mod utils;

pub use config::*;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::SharedLedgerOps;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;

type L2BlockHash = [u8; 32];

pub struct InitParams {
    /// The last known state root
    pub prev_state_root: StorageRootHash,
    /// The last known batch hash
    pub prev_l2_block_hash: L2BlockHash,
}

/// Derives [`InitParams`] from the already-persisted ledger and storage state, **without**
/// (re)initializing genesis.
///
/// This is the common case used both on normal node startup when a chain already exists, and when
/// a listen-mode sequencer is promoted to a block-producing sequencer at runtime: in both cases the
/// state has already been written to the DB and we only need to read back the current head's state
/// root and l2 block hash.
///
/// Callers that need to perform genesis initialization (fresh chain) must handle that separately;
/// this helper assumes the chain already has state.
pub fn read_init_params_from_db<DB: SharedLedgerOps>(
    ledger_db: &DB,
    storage_manager: &ProverStorageManager,
) -> anyhow::Result<InitParams> {
    let prover_storage = storage_manager.create_storage_for_next_l2_height();

    if let Some((number, l2_block)) = ledger_db.get_head_l2_block()? {
        // At least one l2 block was processed.
        return Ok(InitParams {
            prev_state_root: prover_storage.get_root_hash(number.0 + 1)?,
            prev_l2_block_hash: l2_block.hash,
        });
    }

    // Chain was initialized but no L2 blocks were processed yet.
    Ok(InitParams {
        prev_state_root: prover_storage.get_root_hash(1)?,
        prev_l2_block_hash: [0; 32],
    })
}

/// Variant to specify how to start processing L1 blocks
pub enum StartVariant {
    /// Resume from the last scanned L1 block height, the following L1 block will be the next one to process.
    LastScanned(u64),
    /// Start processing from an initial L1 block height
    FromBlock(u64),
}

impl StartVariant {
    /// Returns the actual L1 block height to start processing from based on the variant.
    pub fn start_height(self) -> u64 {
        match self {
            StartVariant::LastScanned(h) => h + 1,
            StartVariant::FromBlock(h) => h,
        }
    }
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
