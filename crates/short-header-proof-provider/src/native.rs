use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::sync::Arc;

use borsh::BorshDeserialize;
use parking_lot::Mutex;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifiableShortHeaderProof;

use super::{ShortHeaderProofProvider, ShortHeaderProofProviderError};

pub struct NativeShortHeaderProofProviderService<Da: DaSpec> {
    pub queried_and_verified_hashes: Arc<Mutex<HashMap<u64, Vec<[u8; 32]>>>>,
    pub ledger_db: LedgerDB,
    pub _phantom: PhantomData<Da>,
    save_hashes: bool,
}

impl<Da: DaSpec> NativeShortHeaderProofProviderService<Da> {
    pub fn new(ledger_db: LedgerDB, save_hashes: bool) -> Self {
        Self {
            ledger_db,
            queried_and_verified_hashes: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
            save_hashes,
        }
    }
}

impl<Da: DaSpec> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
        prev_block_hash: [u8; 32],
        l1_height: u64,
        txs_commitment: [u8; 32],
        coinbase_depth: u8,
        l2_height: u64,
    ) -> Result<bool, ShortHeaderProofProviderError> {
        if let Some(shp_serialized) = self
            .ledger_db
            .get_short_header_proof_by_l1_hash(&block_hash)
            // TODO: Return error here and make process l2 block run again
            .expect("Should save short header proof")
        {
            let shp = Da::ShortHeaderProof::try_from_slice(&shp_serialized)
                .expect("Should deserialize short header proof");

            if let Ok(l1_update_info) = shp.verify() {
                // the contract will return 0000...00 if we are pushing the first L1 block
                // hence we accept given prev_hash
                let prev_hash_cond = prev_block_hash == [0; 32]
                    || prev_block_hash == l1_update_info.prev_header_hash;

                let return_cond = txs_commitment == l1_update_info.tx_commitment
                    && block_hash == l1_update_info.header_hash
                    && prev_hash_cond
                    && l1_height == l1_update_info.block_height
                    && coinbase_depth == l1_update_info.coinbase_txid_merkle_proof_height;

                if return_cond && self.save_hashes {
                    let mut queried_hashes_map = self.queried_and_verified_hashes.lock();

                    queried_hashes_map.try_reserve(1).map_err(|e| {
                        ShortHeaderProofProviderError::VectorAllocationFailed(e.to_string())
                    })?;

                    let entry = queried_hashes_map.entry(l2_height);
                    match entry {
                        std::collections::hash_map::Entry::Occupied(mut occ) => {
                            occ.get_mut().try_reserve(1).map_err(|e| {
                                ShortHeaderProofProviderError::VectorAllocationFailed(e.to_string())
                            })?;
                            occ.get_mut().push(block_hash);
                        }
                        std::collections::hash_map::Entry::Vacant(vac) => {
                            let mut v: Vec<[u8; 32]> = Vec::new();
                            v.try_reserve_exact(1).map_err(|e| {
                                ShortHeaderProofProviderError::VectorAllocationFailed(e.to_string())
                            })?;
                            v.push(block_hash);
                            vac.insert(v);
                        }
                    }
                }

                return Ok(return_cond);
            }
            return Ok(false);
        }
        Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound)
    }

    fn clear_queried_hashes(&self) {
        self.queried_and_verified_hashes.lock().clear();
    }

    fn take_queried_hashes(
        &self,
        l2_range: RangeInclusive<u64>,
    ) -> Result<Vec<[u8; 32]>, ShortHeaderProofProviderError> {
        let mut map = self.queried_and_verified_hashes.lock();
        let mut hashes: Vec<[u8; 32]> = Vec::new();

        for l2_height in l2_range {
            if let Some(taken) = map.remove(&l2_height) {
                hashes.try_reserve(taken.len()).map_err(|e| {
                    ShortHeaderProofProviderError::VectorAllocationFailed(e.to_string())
                })?;
                hashes.extend(taken);
            }
        }

        Ok(hashes)
    }

    fn take_last_queried_hash(&self) -> Option<[u8; 32]> {
        unimplemented!(
            "take_last_queried_hash is not implemented for NativeShortHeaderProofProviderService"
        );
    }
}
