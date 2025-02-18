use std::marker::PhantomData;
#[cfg(feature = "native")]
use std::sync::Arc;

use borsh::BorshDeserialize;
#[cfg(feature = "native")]
use futures::executor::block_on;
use once_cell::sync::OnceCell;
#[cfg(feature = "native")]
use sov_db::ledger_db::LedgerDB;
#[cfg(feature = "native")]
use sov_db::ledger_db::SharedLedgerOps;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;
#[cfg(feature = "native")]
use sov_rollup_interface::services::da::DaService;

/// Short Header Proof Provider
/// This trait is used to get the short header proof by the l1 hash
/// for full nodes and provers to verify sequencer set block info system transaction parameters
pub trait ShortHeaderProofProvider: Send + Sync {
    /// Returns short header proof by the l1 hash
    fn get_and_verify_short_header_proof_by_l1_hash(&self, l1_hash: [u8; 32]) -> bool;
}

pub static SHORT_HEADER_PROOF_PROVIDER: OnceCell<Box<dyn ShortHeaderProofProvider>> =
    OnceCell::new();

#[cfg(feature = "native")]
pub struct NativeShortHeaderProofProviderService<Da: DaService> {
    pub da_service: Arc<Da>,
    pub ledger_db: LedgerDB,
}

#[cfg(feature = "native")]
impl<Da: DaService> NativeShortHeaderProofProviderService<Da> {
    pub fn new(da_service: Arc<Da>, ledger_db: LedgerDB) -> Self {
        Self {
            da_service,
            ledger_db,
        }
    }
}

#[cfg(feature = "native")]
impl<Da: DaService> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(&self, block_hash: [u8; 32]) -> bool {
        let block = block_on(self.da_service.get_block_by_hash(block_hash.into())).unwrap();
        let shp = Da::block_to_short_header_proof(block);
        self.ledger_db
            .put_short_header_proof_by_l1_hash(
                &block_hash,
                &borsh::to_vec(&shp).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof");
        shp.verify().is_ok()
    }
}

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
            if shp.verify().is_ok() {
                return true;
            }
            return false;
        }
        // If proof not found also return false
        false
    }
}
