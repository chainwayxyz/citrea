use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::RwLock;

use borsh::BorshDeserialize;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::ShortHeaderProofProvider;
use crate::ShortHeaderProofProviderError;

pub struct ZkShortHeaderProofProviderService<Da: DaSpec> {
    short_header_proofs: RwLock<VecDeque<([u8; 32], Vec<u8>)>>,
    phantom: PhantomData<Da>,
}

impl<Da: DaSpec> ZkShortHeaderProofProviderService<Da> {
    pub fn new(short_header_proofs: VecDeque<([u8; 32], Vec<u8>)>) -> Self {
        Self {
            short_header_proofs: RwLock::new(short_header_proofs),
            phantom: PhantomData,
        }
    }
}
impl<Da: DaSpec> ShortHeaderProofProvider for ZkShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
    ) -> Result<bool, ShortHeaderProofProviderError> {
        let shp = self
            .short_header_proofs
            .write()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                panic!(
                    "Should have short header proof for l1 hash: {:?}",
                    block_hash
                )
            })
            .1;

        let shp = Da::ShortHeaderProof::try_from_slice(&shp).unwrap();
        Ok(shp.verify().is_ok())
    }
}
