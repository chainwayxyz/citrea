use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use borsh::BorshDeserialize;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::{ShortHeaderProofProvider, ShortHeaderProofProviderError};

pub struct NativeShortHeaderProofProviderService<Da: DaSpec> {
    pub quried_and_verified_hashes: Arc<Mutex<HashMap<u64, [u8; 32]>>>,
    pub ledger_db: LedgerDB,
    pub _phantom: PhantomData<Da>,
}

impl<Da: DaSpec> NativeShortHeaderProofProviderService<Da> {
    pub fn new(ledger_db: LedgerDB) -> Self {
        Self {
            ledger_db,
            quried_and_verified_hashes: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
        }
    }
}

impl<Da: DaSpec> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
        txs_commitment: [u8; 32],
        l2_height: u64,
    ) -> Result<bool, ShortHeaderProofProviderError> {
        println!("Asked for l2 height: {}", l2_height);
        if let Some(shp_serialized) = self
            .ledger_db
            .get_short_header_proof_by_l1_hash(&block_hash)
            // TODO: Return error here and make process l2 block run again
            .expect("Should save short header proof")
        {
            let shp = Da::ShortHeaderProof::try_from_slice(&shp_serialized)
                .expect("Should deserialize short header proof");

            if let Ok(l1_update_info) = shp.verify() {
                println!(
                    "Inserting hash for l2 height: {}, hash: {:?}",
                    l2_height, block_hash
                );
                self.quried_and_verified_hashes
                    .lock()
                    .expect("Should lock quried and verified hashes")
                    .insert(l2_height, block_hash);
                return Ok(txs_commitment == l1_update_info.tx_commitment
                    && block_hash == l1_update_info.header_hash);
            }
            return Ok(false);
        }
        Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound)
    }

    fn clear_queried_hashes(&self) {
        self.quried_and_verified_hashes.lock().unwrap().clear();
    }

    fn take_queried_hashes(&self, l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]> {
        let quried_and_verified_hashes = self.quried_and_verified_hashes.lock().unwrap();
        let mut hashes = Vec::new();
        for l2_height in l2_range {
            if let Some(hash) = quried_and_verified_hashes.get(&l2_height) {
                println!("Taking hash for l2 height: {}, hash: {:?}", l2_height, hash);
                hashes.push(*hash);
            }
        }
        hashes
    }
}
