use std::fmt::Debug;

use alloy_primitives::{U32, U64};
use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::da::LatestDaState;
use sov_rollup_interface::rpc::{
    BatchProofMethodIdRpcResponse, LatestDaStateRpcResponse, LightClientProofOutputRpcResponse,
    LightClientProofResponse,
};
use sov_rollup_interface::zk::light_client_proof::output::{
    BatchProofInfo, LightClientCircuitOutput,
};
use sov_rollup_interface::zk::Proof;

/// Latest da state to verify and apply da block changes
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq)]
pub struct StoredLatestDaState {
    /// Proved DA block's header hash
    /// This is used to compare the previous DA block hash with first batch proof's DA block hash
    pub block_hash: [u8; 32],
    /// Height of the blockchain
    pub block_height: u64,
    /// Total work done in the DA blockchain
    pub total_work: [u8; 32],
    /// Current target bits of DA
    pub current_target_bits: u32,
    /// The time of the first block in the current epoch (the difficulty adjustment timestamp)
    pub epoch_start_time: u32,
    /// The UNIX timestamps in seconds of the previous 11 blocks
    pub prev_11_timestamps: [u32; 11],
}

/// The on-disk format for a light client proof output
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredLightClientProofOutput {
    /// State root of the node after the light client proof
    pub l2_state_root: [u8; 32],
    /// LCP JMT state root
    pub lcp_state_root: [u8; 32],
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    pub light_client_proof_method_id: [u32; 8],
    /// Latest DA state after proof
    pub latest_da_state: StoredLatestDaState,
    /// Unchained batch proofs are proofs that are not consecutive,
    /// hence can not be proven yet kproofs.
    pub unchained_batch_proofs_info: Vec<BatchProofInfo>,
    /// Last l2 height after proof.
    pub last_l2_height: u64,
    /// L2 activation height of the fork and the Method ids of the batch proofs that were verified in the light client proof
    pub batch_proof_method_ids: Vec<(u64, [u32; 8])>,
}

impl From<StoredLightClientProofOutput> for LightClientProofOutputRpcResponse {
    fn from(value: StoredLightClientProofOutput) -> Self {
        Self {
            l2_state_root: value.l2_state_root,
            light_client_proof_method_id: value.light_client_proof_method_id.into(),
            latest_da_state: LatestDaStateRpcResponse {
                block_hash: value.latest_da_state.block_hash,
                block_height: U64::from(value.latest_da_state.block_height),
                total_work: value.latest_da_state.total_work,
                current_target_bits: U32::from(value.latest_da_state.current_target_bits),
                epoch_start_time: U32::from(value.latest_da_state.epoch_start_time),
                prev_11_timestamps: value
                    .latest_da_state
                    .prev_11_timestamps
                    .into_iter()
                    .map(U32::from)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("should have 11 elements"),
            },
            unchained_batch_proofs_info: value
                .unchained_batch_proofs_info
                .into_iter()
                .map(Into::into)
                .collect(),
            last_l2_height: U64::from(value.last_l2_height),
            batch_proof_method_ids: value
                .batch_proof_method_ids
                .into_iter()
                .map(|(height, method_id)| BatchProofMethodIdRpcResponse {
                    height: U64::from(height),
                    method_id: method_id.into(),
                })
                .collect(),
            lcp_state_root: value.lcp_state_root,
        }
    }
}

impl From<LightClientCircuitOutput> for StoredLightClientProofOutput {
    fn from(circuit_output: LightClientCircuitOutput) -> Self {
        let latest_da_state = circuit_output.latest_da_state;
        StoredLightClientProofOutput {
            l2_state_root: circuit_output.l2_state_root,
            light_client_proof_method_id: circuit_output.light_client_proof_method_id,
            latest_da_state: StoredLatestDaState {
                block_hash: latest_da_state.block_hash,
                block_height: latest_da_state.block_height,
                total_work: latest_da_state.total_work,
                current_target_bits: latest_da_state.current_target_bits,
                epoch_start_time: latest_da_state.epoch_start_time,
                prev_11_timestamps: latest_da_state.prev_11_timestamps,
            },
            unchained_batch_proofs_info: circuit_output.unchained_batch_proofs_info,
            last_l2_height: circuit_output.last_l2_height,
            batch_proof_method_ids: circuit_output.batch_proof_method_ids,
            lcp_state_root: circuit_output.lcp_state_root,
        }
    }
}

impl From<StoredLightClientProofOutput> for LightClientCircuitOutput {
    fn from(db_output: StoredLightClientProofOutput) -> Self {
        let latest_da_state = db_output.latest_da_state;
        LightClientCircuitOutput {
            l2_state_root: db_output.l2_state_root,
            light_client_proof_method_id: db_output.light_client_proof_method_id,
            latest_da_state: LatestDaState {
                block_hash: latest_da_state.block_hash,
                block_height: latest_da_state.block_height,
                total_work: latest_da_state.total_work,
                current_target_bits: latest_da_state.current_target_bits,
                epoch_start_time: latest_da_state.epoch_start_time,
                prev_11_timestamps: latest_da_state.prev_11_timestamps,
            },
            unchained_batch_proofs_info: db_output.unchained_batch_proofs_info,
            last_l2_height: db_output.last_l2_height,
            batch_proof_method_ids: db_output.batch_proof_method_ids,
            lcp_state_root: db_output.lcp_state_root,
        }
    }
}

/// The on-disk format for a light client proof
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredLightClientProof {
    /// The proof
    pub proof: Proof,
    /// The light client circuit proof output
    pub light_client_proof_output: StoredLightClientProofOutput,
}

impl From<StoredLightClientProof> for LightClientProofResponse {
    fn from(value: StoredLightClientProof) -> Self {
        Self {
            proof: value.proof,
            light_client_proof_output: LightClientProofOutputRpcResponse::from(
                value.light_client_proof_output,
            ),
        }
    }
}
