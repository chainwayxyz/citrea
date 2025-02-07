use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::CumulativeStateDiff;
use crate::da::DaSpec;
use crate::spec::SpecId;
use crate::zk::StorageRootHash;

/// Because we removed validity condition from everywhere we need to keep it for compatibility
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct OldChainValidityCondition {
    /// Prev hash
    pub prev_hash: [u8; 32],
    /// Block hash
    pub block_hash: [u8; 32],
}

/// The pre fork 1 batch proof circuit output
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct BatchProofCircuitOutputV1<Da: DaSpec> {
    /// The state of the rollup before the transition
    pub initial_state_root: StorageRootHash,
    /// The state of the rollup after the transition
    pub final_state_root: StorageRootHash,
    /// The hash before the state transition
    pub initial_batch_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    pub da_slot_hash: Da::SlotHash,
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    pub sequencer_da_public_key: Vec<u8>,
    /// An additional validity condition for the state transition which needs
    /// to be checked outside of the zkVM circuit. This typically corresponds to
    /// some claim about the DA layer history, such as (X) is a valid block on the DA layer
    /// This should be Da::ValidityCondition however we removed but we need to keep it for compatibility
    /// That's why we use OldChainValidityCondition instead of Da::ValidityCondition
    /// This is from old bitcoin da spec
    pub validity_condition: OldChainValidityCondition,
    /// The final spec id after state transition is completed.
    pub last_active_spec_id: SpecId,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
}
