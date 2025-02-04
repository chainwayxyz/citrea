use alloc::collections::VecDeque;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::da::DaSpec;
use crate::mmr::{MMRChunk, MMRInclusionProof};

/// The input of light client proof
#[derive(BorshDeserialize, BorshSerialize)]
pub struct LightClientCircuitInput<Da: DaSpec> {
    /// The `crate::da::DaData` that are being processed as blobs.
    pub da_data: Vec<Da::BlobTransaction>,
    /// The inclusion proof for all DA data.
    pub inclusion_proof: Da::InclusionMultiProof,
    /// The completeness proof for all DA data.
    pub completeness_proof: Da::CompletenessProof,
    /// DA block header that the batch proofs were found in.
    pub da_block_header: Da::BlockHeader,
    /// Light client proof method id
    pub light_client_proof_method_id: [u32; 8],
    /// Light client proof output
    /// Optional because the first light client proof doesn't have a previous proof
    pub previous_light_client_proof_journal: Option<Vec<u8>>,
    /// Hints for the guest MMR tree.
    pub mmr_hints: VecDeque<(MMRChunk, MMRInclusionProof)>,
    /// Hint for which proofs are expected to fail
    ///
    /// Note: Indices are u32 even though we don't expect that many proofs
    /// on a DA block. However storing them as u32 is more efficient in zkVMs
    /// and just to be sure we don't overflow u8.
    pub expected_to_fail_hint: Vec<u32>,
}
