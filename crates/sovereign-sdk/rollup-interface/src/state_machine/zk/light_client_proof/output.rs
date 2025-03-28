use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::da::LatestDaState;
use crate::zk::StorageRootHash;

/// The output of light client proof
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq)]
pub struct LightClientCircuitOutput {
    /// State root of the node after the light client proof
    pub l2_state_root: StorageRootHash,
    /// Light client proof JMT state root
    pub lcp_state_root: StorageRootHash,
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    pub light_client_proof_method_id: [u32; 8],
    /// Latest da state output of the previous light client proof
    /// If None, initial hardcoded da block will be used for verification
    pub latest_da_state: LatestDaState,
    /// Last l2 height the light client proof verifies
    pub last_l2_height: u64,
    /// The last sequencer commitment index of the last fully stitched and verified batch proof
    pub last_sequencer_commitment_index: u32,
}

/// The batch proof that was not verified in the light client circuit because it was missing another proof for state root chaining
/// This struct is used in the light client circuit jmt to store info about unchained batch proofs' commitments
/// The circuit will query by commitment index to get this info of state transition
/// Initial and final state root belong to the commitment it self not the whole batch proof
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq, Serialize, Deserialize)]
pub struct VerifiedStateTransitionForSequencerCommitmentIndex {
    /// Initial state root of the batch proof
    pub initial_state_root: [u8; 32],
    /// Final state root of the batch proof
    pub final_state_root: [u8; 32],
    /// The last processed l2 height in the batch proof
    pub last_l2_height: u64,
}

impl VerifiedStateTransitionForSequencerCommitmentIndex {
    /// Create a new `BatchProofInfo` instance.
    pub fn new(
        initial_state_root: [u8; 32],
        final_state_root: [u8; 32],
        last_l2_height: u64,
    ) -> Self {
        Self {
            initial_state_root,
            final_state_root,
            last_l2_height,
        }
    }
}
