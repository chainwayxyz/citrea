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
    pub queried_and_verified_hashes: Arc<Mutex<HashMap<u64, Vec<[u8; 32]>>>>,
    pub ledger_db: LedgerDB,
    pub _phantom: PhantomData<Da>,
}

impl<Da: DaSpec> NativeShortHeaderProofProviderService<Da> {
    pub fn new(ledger_db: LedgerDB) -> Self {
        Self {
            ledger_db,
            queried_and_verified_hashes: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
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

                if return_cond {
                    self.queried_and_verified_hashes
                        .lock()
                        .expect("Should lock queried and verified hashes")
                        .entry(l2_height)
                        .and_modify(|f| f.push(block_hash))
                        .or_insert(vec![block_hash]);
                }

                return Ok(return_cond);
            }
            return Ok(false);
        }
        Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound)
    }

    fn clear_queried_hashes(&self) {
        self.queried_and_verified_hashes.lock().unwrap().clear();
    }

    fn take_queried_hashes(&self, l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]> {
        let queried_and_verified_hashes = self.queried_and_verified_hashes.lock().unwrap();
        let mut hashes = Vec::new();
        for l2_height in l2_range {
            if let Some(hash) = queried_and_verified_hashes.get(&l2_height) {
                hashes.extend(hash.clone());
            }
        }
        hashes
    }

    fn take_last_queried_hash(&self) -> Option<[u8; 32]> {
        unimplemented!(
            "take_last_queried_hash is not implemented for NativeShortHeaderProofProviderService"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_mock_da::verifier::MockShortHeaderProof;
    use sov_mock_da::MockDaSpec;
    use tempfile::TempDir;

    use super::*;

    fn setup_test_db() -> (TempDir, LedgerDB) {
        let temp_dir = TempDir::new().unwrap();
        let ledger_db =
            LedgerDB::with_config(&RocksdbConfig::new(Path::new(temp_dir.path()), None, None))
                .unwrap();
        (temp_dir, ledger_db)
    }

    #[test]
    fn test_successful_short_header_proof_verification() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

        let block_hash = [1u8; 32];
        let prev_block_hash = [2u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 100;
        let coinbase_depth = 1;
        let l2_height = 50;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: prev_block_hash,
            txs_commitment,
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes)
            .unwrap();

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                l1_height,
                txs_commitment,
                coinbase_depth,
                l2_height,
            )
            .unwrap();

        assert!(ok);

        let queried_hashes = service.queried_and_verified_hashes.lock().unwrap();
        assert!(queried_hashes.contains_key(&l2_height));
        assert_eq!(queried_hashes.get(&l2_height).unwrap(), &vec![block_hash]);
    }

    #[test]
    fn test_first_block_verification() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

        let block_hash = [1u8; 32];
        // indicates that this is the first block
        let prev_block_hash = [0u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 1;
        let coinbase_depth = 1;
        let l2_height = 1;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [4u8; 32],
            txs_commitment,
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes)
            .unwrap();

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                l1_height,
                txs_commitment,
                coinbase_depth,
                l2_height,
            )
            .unwrap();

        assert!(ok);
    }

    #[test]
    fn test_proof_not_found() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db);

        let block_hash = [1u8; 32];
        let result = service.get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [2u8; 32], 100, [3u8; 32], 1, 50,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ShortHeaderProofProviderError::ShortHeaderProofNotFound
        ));
    }

    #[test]
    fn test_invalid_proof_verification() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

        let block_hash = [1u8; 32];
        let prev_block_hash = [2u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 100;
        let coinbase_depth = 1;
        let l2_height = 50;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [5u8; 32],
            txs_commitment: [6u8; 32],
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes)
            .unwrap();

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                // different l1 height
                l1_height + 1,
                txs_commitment,
                coinbase_depth,
                l2_height,
            )
            .unwrap();
        assert!(!ok);

        let queried_hashes = service.queried_and_verified_hashes.lock().unwrap();
        assert!(!queried_hashes.contains_key(&l2_height));
    }

    #[test]
    fn test_clear_queried_hashes() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

        let block_hash = [1u8; 32];
        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [2u8; 32],
            txs_commitment: [3u8; 32],
            height: 100,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes)
            .unwrap();

        service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash, [2u8; 32], 100, [3u8; 32], 1, 50,
            )
            .unwrap();

        assert!(!service
            .queried_and_verified_hashes
            .lock()
            .unwrap()
            .is_empty());

        service.clear_queried_hashes();

        assert!(service
            .queried_and_verified_hashes
            .lock()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_take_queried_hashes() {
        let (_temp_dir, ledger_db) = setup_test_db();
        let service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

        let block_hash1 = [1u8; 32];
        let block_hash2 = [2u8; 32];

        let mock_proof1 = MockShortHeaderProof {
            header_hash: block_hash1,
            prev_header_hash: [3u8; 32],
            txs_commitment: [4u8; 32],
            height: 100,
        };
        let proof_bytes = borsh::to_vec(&mock_proof1).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash1, proof_bytes)
            .unwrap();

        service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash1,
                [3u8; 32],
                100,
                [4u8; 32],
                1,
                50,
            )
            .unwrap();

        let mock_proof2 = MockShortHeaderProof {
            header_hash: block_hash2,
            prev_header_hash: [5u8; 32],
            txs_commitment: [6u8; 32],
            height: 101,
        };
        let proof_bytes = borsh::to_vec(&mock_proof2).unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash2, proof_bytes)
            .unwrap();

        service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash2,
                [5u8; 32],
                101,
                [6u8; 32],
                1,
                51,
            )
            .unwrap();

        let hashes = service.take_queried_hashes(50..=51);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&block_hash1));
        assert!(hashes.contains(&block_hash2));

        let hashes = service.take_queried_hashes(50..=50);
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains(&block_hash1));
    }
}
