use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::CumulativeStateDiff;
use crate::zk::StorageRootHash;

/// The public output of a SNARK batch proof in Sovereign, this struct makes a claim that
/// the state of the rollup has transitioned from `initial_state_root` to `final_state_root`
///
/// The period of time covered by a state transition proof is a range of L2 blocks whose sequencer
/// commitments are included in the DA slot with hash `da_slot_hash`. The range is inclusive.
/// Some fields (prev_soft_confirmation_hash, final_soft_confirmation_hash and last_l2_height)
/// Will be 0 for pre fork 1 proofs because this is a new output format and those fields
/// did not exist pre fork 1
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BatchProofCircuitOutputV3 {
    /// The state of the rollup before the transition
    pub initial_state_root: StorageRootHash,
    /// The state of the rollup after the transition
    pub final_state_root: StorageRootHash,
    /// The hash of the last soft confirmation in the state transition
    /// This will be [0; 32] for pre fork 1 proofs
    pub final_soft_confirmation_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The last processed l2 height in the processed sequencer commitments.
    /// This will be 0 for pre fork 1 proofs
    pub last_l2_height: u64,
    /// Hashes inside sequencer commitmentes that were processed.
    pub sequencer_commitment_merkle_roots: Vec<[u8; 32]>,
    /// L1 hashes added to the Bitocin light client contract
    pub l1_hashes_added_to_light_client_contract: Vec<[u8; 32]>,
}
