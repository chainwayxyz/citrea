use borsh::{BorshDeserialize, BorshSerialize};

use crate::da::DaSpec;
use crate::witness::Witness;

/// The input of light client proof
#[derive(BorshDeserialize, BorshSerialize)]
pub struct LightClientCircuitInput<Da: DaSpec> {
    /// The inclusion proof for all DA data.
    pub inclusion_proof: Da::InclusionMultiProof,
    /// The completeness proof for all DA data.
    pub completeness_proof: Da::CompletenessProof,
    /// DA block header that the batch proofs were found in.
    pub da_block_header: Da::BlockHeader,
    /// Light client proof method id
    pub light_client_proof_method_id: [u32; 8],
    /// Previous light client proof
    /// Optional because the first light client proof doesn't have a previous proof
    pub previous_light_client_proof: Option<Vec<u8>>,
    /// Witness for the light client state
    pub witness: Witness,
}
