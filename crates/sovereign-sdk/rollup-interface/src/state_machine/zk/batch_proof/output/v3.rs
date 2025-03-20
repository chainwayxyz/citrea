use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::CumulativeStateDiff;
use crate::zk::StorageRootHash;

/// The public output of a SNARK batch proof in Sovereign, this struct makes a claim that
/// the state of the rollup has transitioned from `initial_state_root` to `final_state_root`
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BatchProofCircuitOutputV3 {
    /// The state of the rollup before the transition
    pub initial_state_root: StorageRootHash,
    /// The state of the rollup after the transition
    pub final_state_root: StorageRootHash,
    /// The hash of the last l2 block in the state transition
    /// This will be [0; 32] for pre fork 1 proofs
    pub final_l2_block_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The last processed l2 height in the processed sequencer commitments.
    /// This will be 0 for pre fork 1 proofs
    pub last_l2_height: u64,
    /// Hashes inside sequencer commitments that were processed.
    pub sequencer_commitment_hashes: Vec<[u8; 32]>,
    /// The range of sequencer commitments that were processed.
    pub sequencer_commitment_index_range: (u32, u32),
    /// L1 hashes added to the Bitcoin light client contract
    pub last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
    /// The index of the previous commitment that was given as input in the batch proof
    pub previous_commitment_index: Option<u32>,
    /// The hash of the previous commitment that was given as input in the batch proof
    pub previous_commitment_hash: Option<[u8; 32]>,
}
