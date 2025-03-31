use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::RefCount;

/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<RefCount<[u8]>, Option<RefCount<[u8]>>>;

/// Versioned Batch Proof Output
#[derive(Debug, BorshDeserialize, BorshSerialize)]
#[repr(u8)]
pub enum BatchProofCircuitOutput {
    /// V3 batch proof output
    V3(v3::BatchProofCircuitOutputV3),
}

impl BatchProofCircuitOutput {
    /// Get the initial state root
    pub fn initial_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => *output.state_roots.first().unwrap(),
        }
    }

    /// Get the final state root
    pub fn final_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => *output.state_roots.last().unwrap(),
        }
    }

    /// Returns the state roots
    pub fn state_roots(&self) -> Vec<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V3(output) => output.state_roots.clone(),
        }
    }

    /// Get the final soft confirmation hash
    pub fn final_l2_block_hash(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => output.final_l2_block_hash,
        }
    }

    /// Get sequencer commitment hashes
    pub fn sequencer_commitment_hashes(&self) -> Vec<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V3(output) => output.sequencer_commitment_hashes.clone(),
        }
    }

    /// Get sequencer commitment index range
    pub fn sequencer_commitment_index_range(&self) -> (u32, u32) {
        match self {
            BatchProofCircuitOutput::V3(output) => output.sequencer_commitment_index_range,
        }
    }

    /// Get the last L1 hash on the Bitcoin light client contract
    pub fn last_l1_hash_on_bitcoin_light_client_contract(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => {
                output.last_l1_hash_on_bitcoin_light_client_contract
            }
        }
    }

    /// Get the state diff produced by the Zk proof
    pub fn state_diff(&self) -> &CumulativeStateDiff {
        match self {
            BatchProofCircuitOutput::V3(output) => &output.state_diff,
        }
    }

    /// Get the last L2 height
    pub fn last_l2_height(&self) -> u64 {
        match self {
            BatchProofCircuitOutput::V3(output) => output.last_l2_height,
        }
    }

    /// Get the previous commitment index
    pub fn previous_commitment_index(&self) -> Option<u32> {
        match self {
            BatchProofCircuitOutput::V3(output) => output.previous_commitment_index,
        }
    }

    /// Get the previous commitment hash
    pub fn previous_commitment_hash(&self) -> Option<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V3(output) => output.previous_commitment_hash,
        }
    }
}
