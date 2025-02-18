use std::marker::PhantomData;

use borsh::BorshDeserialize;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::ShortHeaderProofProvider;

pub struct ZkShortHeaderProofProviderService<Da: DaSpec> {
    short_header_proofs: Vec<([u8; 32], Vec<u8>)>,
    phantom: PhantomData<Da>,
}
impl<Da: DaSpec> ZkShortHeaderProofProviderService<Da> {
    pub fn new(short_header_proofs: Vec<([u8; 32], Vec<u8>)>) -> Self {
        Self {
            short_header_proofs,
            phantom: PhantomData,
        }
    }
}
impl<Da: DaSpec> ShortHeaderProofProvider for ZkShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(&self, block_hash: [u8; 32]) -> bool {
        if let Some(pos) = self
            .short_header_proofs
            .iter()
            .position(|(l1_hash, _)| l1_hash == &block_hash)
        {
            let shp =
                Da::ShortHeaderProof::try_from_slice(&self.short_header_proofs[pos].1).unwrap();
            return shp.verify().is_ok();
        }
        // If proof not found also return false
        false
    }
}
