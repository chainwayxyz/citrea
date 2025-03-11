use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::RefCount;

/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<RefCount<[u8]>, Option<RefCount<[u8]>>>;

/// Versioned Batch Proof Output
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub enum BatchProofCircuitOutput {
    /// V3 batch proof output
    V3(v3::BatchProofCircuitOutputV3),
}

impl BatchProofCircuitOutput {
    /// Get the initial state root
    pub fn initial_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => output.initial_state_root,
        }
    }

    /// Get the final state root
    pub fn final_state_root(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => output.final_state_root,
        }
    }

    /// Get the final soft confirmation hash
    pub fn final_soft_confirmation_hash(&self) -> [u8; 32] {
        match self {
            BatchProofCircuitOutput::V3(output) => output.final_soft_confirmation_hash,
        }
    }

    /// Get sequencer commitment merkle roots
    pub fn sequencer_commitment_merkle_roots(&self) -> Vec<[u8; 32]> {
        match self {
            BatchProofCircuitOutput::V3(output) => output.sequencer_commitment_merkle_roots.clone(),
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
}
