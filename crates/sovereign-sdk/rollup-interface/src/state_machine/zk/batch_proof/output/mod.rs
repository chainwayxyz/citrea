use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::RefCount;

/// Genesis output module
pub mod v1;
/// Kumquat output module
pub mod v2;
/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<RefCount<[u8]>, Option<RefCount<[u8]>>>;

/// Versioned Batch Proof Output
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub enum BatchProofCircuitOutput {
    /// V1 batch proof output
    V1(v1::BatchProofCircuitOutputV1),
    /// V2 batch proof output
    V2(v2::BatchProofCircuitOutputV2),
    /// V3 batch proof output
    V3(v3::BatchProofCircuitOutputV3),
}

impl BatchProofCircuitOutput {
    /// Get the initial state root
    pub fn initial_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V1(output) => output.initial_state_root,
            BatchProofCircuitOutput::V2(output) => output.initial_state_root,
            BatchProofCircuitOutput::V3(output) => output.initial_state_root,
        }
    }

    /// Get the final state root
    pub fn final_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V1(output) => output.final_state_root,
            BatchProofCircuitOutput::V2(output) => output.final_state_root,
            BatchProofCircuitOutput::V3(output) => output.final_state_root,
        }
    }

    /// Get the final soft confirmation hash
    pub fn final_soft_confirmation_hash(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V1(_) => [0; 32],
            BatchProofCircuitOutput::V2(output) => output.final_soft_confirmation_hash,
            BatchProofCircuitOutput::V3(output) => output.final_soft_confirmation_hash,
        }
    }

    /// Get sequencer commitment hashes
    pub fn sequencer_commitment_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V1(_) => vec![],
            BatchProofCircuitOutput::V2(_) => vec![],
            BatchProofCircuitOutput::V3(output) => output.sequencer_commitment_hashes.clone(),
        }
    }

    /// Get sequencer commitment index range
    pub fn sequencer_commitment_index_range(&self) -> (u32, u32) {
        match self {
            BatchProofCircuitOutput::V1(_) => (0, 0),
            BatchProofCircuitOutput::V2(_) => (0, 0),
            BatchProofCircuitOutput::V3(output) => output.sequencer_commitment_index_range,
        }
    }

    /// Get the last L1 hash on the Bitcoin light client contract
    pub fn last_l1_hash_on_bitcoin_light_client_contract(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V1(_) => [0; 32],
            BatchProofCircuitOutput::V2(_) => [0; 32],
            BatchProofCircuitOutput::V3(output) => {
                output.last_l1_hash_on_bitcoin_light_client_contract
            }
        }
    }

    /// Get the state diff produced by the Zk proof
    pub fn state_diff(&self) -> &CumulativeStateDiff {
        match self {
            BatchProofCircuitOutput::V1(output) => &output.state_diff,
            BatchProofCircuitOutput::V2(output) => &output.state_diff,
            BatchProofCircuitOutput::V3(output) => &output.state_diff,
        }
    }

    /// Get the last L2 height
    pub fn last_l2_height(&self) -> u64 {
        match self {
            BatchProofCircuitOutput::V1(_) => 0,
            BatchProofCircuitOutput::V2(output) => output.last_l2_height,
            BatchProofCircuitOutput::V3(output) => output.last_l2_height,
        }
    }

    /// Get the previous commitment index
    pub fn previous_commitment_index(&self) -> Option<u32> {
        match self {
            BatchProofCircuitOutput::V1(_) => None,
            BatchProofCircuitOutput::V2(_) => None,
            BatchProofCircuitOutput::V3(output) => output.previous_commitment_index,
        }
    }

    /// Get the previous commitment hash
    pub fn previous_commitment_hash(&self) -> Option<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V1(_) => None,
            BatchProofCircuitOutput::V2(_) => None,
            BatchProofCircuitOutput::V3(output) => output.previous_commitment_hash,
        }
    }
}
