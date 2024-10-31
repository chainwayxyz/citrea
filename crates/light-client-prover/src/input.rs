use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::da::DaSpec;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct LightClientCircuitInput<Da: DaSpec> {
    pub da_data: Vec<Da::BlobTransaction>,
    pub inclusion_proof: Da::InclusionMultiProof,
    pub completeness_proof: Da::CompletenessProof,
    pub da_block_header: Da::BlockHeader,

    pub batch_prover_da_pub_key: Vec<u8>,
    pub batch_proof_method_id: [u32; 8],
    pub batch_proof_journals: Vec<Vec<u8>>,
}
