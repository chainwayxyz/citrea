use std::fmt::Debug;

use alloy_primitives::{U32, U64};
use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::rpc::{
    BatchProofOutputRpcResponse, BatchProofResponse, VerifiedBatchProofResponse,
};
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::CumulativeStateDiff;
use sov_rollup_interface::zk::Proof;

/// The on-disk format for a state transition.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
pub struct StoredBatchProofOutput {
    /// The state of the rollup before the transition
    pub initial_state_root: Vec<u8>,
    /// The state of the rollup after the transition
    pub final_state_root: Vec<u8>,
    /// The hash of the last soft confirmation before the state transition
    pub prev_soft_confirmation_hash: [u8; 32],
    /// The hash of the last soft confirmation in the state transition
    pub final_soft_confirmation_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    pub da_slot_hash: [u8; 32],
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    pub sequencer_da_public_key: Vec<u8>,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
    /// The last processed l2 height in the processed sequencer commitments.
    pub last_l2_height: u64,
}

// #[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
// pub enum StoredBatchProofOutput {
//     V1(BatchProofCircuitOutputV1),
// }

/// The on-disk format for a proof. Stores the tx id of the proof sent to da, proof data and state transition
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
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

/// The on-disk format for a proof verified by full node. Stores proof data and state transition
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
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
        Self {
            initial_state_root: value.initial_state_root,
            final_state_root: value.final_state_root,
            state_diff: value.state_diff,
            da_slot_hash: value.da_slot_hash,
            sequencer_da_public_key: value.sequencer_da_public_key,
            sequencer_public_key: value.sequencer_public_key,
            sequencer_commitments_range: (
                U32::from(value.sequencer_commitments_range.0),
                U32::from(value.sequencer_commitments_range.1),
            ),
            preproven_commitments: value.preproven_commitments,
            prev_soft_confirmation_hash: value.prev_soft_confirmation_hash,
            final_soft_confirmation_hash: value.final_soft_confirmation_hash,
            last_l2_height: U64::from(value.last_l2_height),
        }
    }
}
