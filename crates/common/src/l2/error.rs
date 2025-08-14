use sov_rollup_interface::stf::StateTransitionError;
use thiserror::Error;

/// Error types that can occur during L2 block synchronization
#[derive(Debug, Error)]
pub enum L2SyncerError {
    /// DA not synced yet
    #[error("Blockhash not found: {0:?}")]
    MissingDaBlock([u8; 32]),

    #[error("Previous hash mismatch at height {height}: expected {expected}, got {got}")]
    PreviousHashMismatch {
        height: u64,
        expected: String,
        got: String,
    },

    #[error("Post state root mismatch at height {height}: expected {expected}, got {got}")]
    PostStateRootMismatch {
        height: u64,
        expected: String,
        got: String,
    },

    #[error("STF error: {0}")]
    ApplyBlockError(StateTransitionError),

    #[error(transparent)]
    SliceConversion(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
