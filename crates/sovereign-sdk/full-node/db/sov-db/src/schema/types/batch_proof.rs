use std::fmt::Debug;

use alloy_primitives::U64;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::rpc::{
    BatchProofOutputRpcResponse, BatchProofResponse, SerializableHash, VerifiedBatchProofResponse,
};
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::Proof;

/// The on-disk format for a state transition.
#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum StoredBatchProofOutput {
    /// V3 batch proof output wrapper
    V3(BatchProofCircuitOutputV3),
}

/// The on-disk format for a proof. Stores the tx id of the proof sent to da, proof data and state transition
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct StoredBatchProof {
    /// Tx id
    pub l1_tx_id: [u8; 32],
    /// Proof
    pub proof: Proof,
    /// Output
    pub proof_output: StoredBatchProofOutput,
}

impl From<StoredBatchProof> for BatchProofResponse {
    fn from(value: StoredBatchProof) -> Self {
        Self {
            l1_tx_id: value.l1_tx_id,
            proof: value.proof,
            proof_output: BatchProofOutputRpcResponse::from(value.proof_output),
        }
    }
}

impl From<BatchProofCircuitOutput> for StoredBatchProofOutput {
    fn from(value: BatchProofCircuitOutput) -> Self {
        match value {
            BatchProofCircuitOutput::V3(value) => Self::V3(value),
        }
    }
}

impl From<BatchProofCircuitOutputV3> for StoredBatchProofOutput {
    fn from(value: BatchProofCircuitOutputV3) -> Self {
        Self::V3(value)
    }
}

/// The on-disk format for a proof verified by full node. Stores proof data and state transition
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub struct StoredVerifiedProof {
    /// Verified Proof
    pub proof: Proof,
    /// State transition
    pub proof_output: StoredBatchProofOutput,
}

impl From<StoredVerifiedProof> for VerifiedBatchProofResponse {
    fn from(value: StoredVerifiedProof) -> Self {
        Self {
            proof: value.proof,
            proof_output: BatchProofOutputRpcResponse::from(value.proof_output),
        }
    }
}

impl From<StoredBatchProofOutput> for BatchProofOutputRpcResponse {
    fn from(value: StoredBatchProofOutput) -> Self {
        match value {
            StoredBatchProofOutput::V3(value) => Self {
                initial_state_root: value.initial_state_root.to_vec(),
                final_state_root: value.final_state_root.to_vec(),
                state_diff: value.state_diff,
                da_slot_hash: None,
                sequencer_da_public_key: vec![],
                sequencer_public_key: vec![],
                sequencer_commitments_range: None,
                preproven_commitments: None,
                prev_l2_block_hash: None,
                final_l2_block_hash: Some(SerializableHash(value.final_l2_block_hash)),
                last_l2_height: Some(U64::from(value.last_l2_height)),
                last_active_spec_id: None,
                last_l1_hash_on_bitcoin_light_client_contract: Some(SerializableHash(
                    value.last_l1_hash_on_bitcoin_light_client_contract,
                )),
            },
        }
    }
}
