use std::fmt::Debug;

use alloy_primitives::{U32, U64, U8};
use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::rpc::{
    BatchProofOutputRpcResponse, BatchProofResponse, SerializableHash, VerifiedBatchProofResponse,
};
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::v2::BatchProofCircuitOutputV2;
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::Proof;

/// The on-disk format for a state transition.
#[derive(Debug, BorshDeserialize, BorshSerialize)]
pub enum StoredBatchProofOutput {
    /// V1 batch proof output wrapper
    V1(BatchProofCircuitOutputV1),
    /// V2 batch proof output wrapper
    V2(BatchProofCircuitOutputV2),
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

impl From<BatchProofCircuitOutputV1> for StoredBatchProofOutput {
    fn from(value: BatchProofCircuitOutputV1) -> Self {
        Self::V1(value)
    }
}

impl From<BatchProofCircuitOutputV2> for StoredBatchProofOutput {
    fn from(value: BatchProofCircuitOutputV2) -> Self {
        Self::V2(value)
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
            StoredBatchProofOutput::V1(value) => Self {
                initial_state_root: value.initial_state_root.to_vec(),
                final_state_root: value.final_state_root.to_vec(),
                state_diff: value.state_diff,
                da_slot_hash: Some(SerializableHash(value.da_slot_hash)),
                sequencer_da_public_key: value.sequencer_da_public_key,
                sequencer_public_key: value.sequencer_public_key,
                sequencer_commitments_range: Some((
                    U32::from(value.sequencer_commitments_range.0),
                    U32::from(value.sequencer_commitments_range.1),
                )),
                preproven_commitments: Some(value.preproven_commitments),
                prev_soft_confirmation_hash: Some(SerializableHash(value.initial_batch_hash)),
                final_soft_confirmation_hash: None,
                last_l2_height: None,
                last_active_spec_id: Some(U8::from(value.last_active_spec_id as u8)),
                l1_hashes_added_to_light_client_contract: vec![],
            },
            StoredBatchProofOutput::V2(value) => Self {
                initial_state_root: value.initial_state_root.to_vec(),
                final_state_root: value.final_state_root.to_vec(),
                state_diff: value.state_diff,
                da_slot_hash: Some(SerializableHash(value.da_slot_hash)),
                sequencer_da_public_key: value.sequencer_da_public_key,
                sequencer_public_key: value.sequencer_public_key,
                sequencer_commitments_range: Some((
                    U32::from(value.sequencer_commitments_range.0),
                    U32::from(value.sequencer_commitments_range.1),
                )),
                preproven_commitments: Some(value.preproven_commitments),
                prev_soft_confirmation_hash: Some(SerializableHash(
                    value.prev_soft_confirmation_hash,
                )),
                final_soft_confirmation_hash: Some(SerializableHash(
                    value.final_soft_confirmation_hash,
                )),
                last_l2_height: Some(U64::from(value.last_l2_height)),
                last_active_spec_id: None,
                l1_hashes_added_to_light_client_contract: vec![],
            },
            StoredBatchProofOutput::V3(value) => Self {
                initial_state_root: value.initial_state_root.to_vec(),
                final_state_root: value.final_state_root.to_vec(),
                state_diff: value.state_diff,
                da_slot_hash: None,
                sequencer_da_public_key: vec![],
                sequencer_public_key: vec![],
                sequencer_commitments_range: None,
                preproven_commitments: None,
                prev_soft_confirmation_hash: None,
                final_soft_confirmation_hash: Some(SerializableHash(
                    value.final_soft_confirmation_hash,
                )),
                last_l2_height: Some(U64::from(value.last_l2_height)),
                last_active_spec_id: None,
                l1_hashes_added_to_light_client_contract: value
                    .l1_hashes_added_to_light_client_contract
                    .iter()
                    .map(|v| SerializableHash(*v))
                    .collect(),
            },
        }
    }
}
