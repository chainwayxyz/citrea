#[cfg(feature = "native")]
use std::sync::Arc;

#[cfg(feature = "native")]
use futures::executor::block_on;
use once_cell::sync::OnceCell;
use sov_rollup_interface::da::VerifableShortHeaderProof;
#[cfg(feature = "native")]
use sov_rollup_interface::services::da::DaService;

/// Short Header Proof Provider
/// This trait is used to get the short header proof by the l1 hash
/// for full nodes and provers to verify sequencer set block info system transaction parameters
pub trait ShortHeaderProofProvider {
    /// Returns short header proof by the l1 hash
    fn get_and_verify_short_header_proof_by_l1_hash(&self, l1_hash: [u8; 32]) -> bool;
}

pub const SHORT_HEADER_PROOF_PROVIDER: OnceCell<Box<dyn ShortHeaderProofProvider>> =
    OnceCell::new();

#[cfg(feature = "native")]
pub struct NativeShortHeaderProofProviderService<Da: DaService> {
    pub da_service: Arc<Da>,
}

#[cfg(feature = "native")]
impl<Da: DaService> NativeShortHeaderProofProviderService<Da> {
    pub fn new(da_service: Arc<Da>) -> Self {
        Self { da_service }
    }
}

#[cfg(feature = "native")]
impl<Da: DaService> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(&self, block_hash: [u8; 32]) -> bool {
        // let block = self.da_service.get_block_at(block_height)?;
        let block = block_on(self.da_service.get_block_by_hash(block_hash.into())).unwrap();
        let shp = Da::block_to_short_header_proof(block);
        match shp.verify() {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

pub struct ZkShortHeaderProofProviderService {}
impl ZkShortHeaderProofProviderService {
    pub fn new() -> Self {
        Self {}
    }
}
impl ShortHeaderProofProvider for ZkShortHeaderProofProviderService {
    fn get_and_verify_short_header_proof_by_l1_hash(&self, block_hash: [u8; 32]) -> bool {
        // TODO: Implement getter for Zkvm
        unimplemented!()
    }
}
