use std::sync::Arc;

use futures::executor::block_on;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_rollup_interface::da::VerifableShortHeaderProof;
use sov_rollup_interface::services::da::DaService;

use super::ShortHeaderProofProvider;

pub struct NativeShortHeaderProofProviderService<Da: DaService> {
    pub da_service: Arc<Da>,
    pub ledger_db: LedgerDB,
}

impl<Da: DaService> NativeShortHeaderProofProviderService<Da> {
    pub fn new(da_service: Arc<Da>, ledger_db: LedgerDB) -> Self {
        Self {
            da_service,
            ledger_db,
        }
    }
}

impl<Da: DaService> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(&self, block_hash: [u8; 32]) -> bool {
        let block = block_on(self.da_service.get_block_by_hash(block_hash.into())).unwrap();
        let shp = Da::block_to_short_header_proof(block);
        self.ledger_db
            .put_short_header_proof_by_l1_hash(
                &block_hash,
                borsh::to_vec(&shp).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof");
        shp.verify().is_ok()
    }
}
