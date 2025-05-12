use std::cell::RefCell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::ops::RangeInclusive;

use borsh::BorshDeserialize;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::ShortHeaderProofProvider;
use crate::ShortHeaderProofProviderError;

pub struct ZkShortHeaderProofProviderService<Da: DaSpec> {
    last_queried_and_verified_hash: RefCell<Option<[u8; 32]>>,
    short_header_proofs: RefCell<VecDeque<Vec<u8>>>,
    phantom: PhantomData<Da>,
}

impl<Da: DaSpec> ZkShortHeaderProofProviderService<Da> {
    pub fn new(short_header_proofs: VecDeque<Vec<u8>>) -> Self {
        Self {
            short_header_proofs: RefCell::new(short_header_proofs),
            last_queried_and_verified_hash: RefCell::new(None),
            phantom: PhantomData,
        }
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl<Da: DaSpec> Send for ZkShortHeaderProofProviderService<Da> {}
unsafe impl<Da: DaSpec> Sync for ZkShortHeaderProofProviderService<Da> {}

impl<Da: DaSpec> ShortHeaderProofProvider for ZkShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
        prev_block_hash: [u8; 32],
        l1_height: u64,
        txs_commitment: [u8; 32],
        coinbase_depth: u8,
        _l2_height: u64,
    ) -> Result<bool, ShortHeaderProofProviderError> {
        let shp = self
            .short_header_proofs
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| {
                panic!(
                    "Should have short header proof for l1 hash: {:?}",
                    block_hash
                )
            });

        let shp = Da::ShortHeaderProof::try_from_slice(&shp)
            .expect("Should deserialize short header proof");

        if let Ok(l1_update_info) = shp.verify() {
            let prev_hash_cond =
                prev_block_hash == [0; 32] || prev_block_hash == l1_update_info.prev_header_hash;

            let return_cond = txs_commitment == l1_update_info.tx_commitment
                && block_hash == l1_update_info.header_hash
                && prev_hash_cond
                && l1_height == l1_update_info.block_height
                && coinbase_depth == l1_update_info.coinbase_txid_merkle_proof_height;

            if return_cond {
                *self.last_queried_and_verified_hash.borrow_mut() = Some(block_hash);
            }

            return Ok(return_cond);
        }
        Ok(false)
    }

    fn clear_queried_hashes(&self) {
        unimplemented!("clear_queried_hashes is not implemented for zk provider");
    }

    fn take_queried_hashes(&self, _l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]> {
        unimplemented!("take_queried_hashes is not implemented for zk provider");
    }

    fn take_last_queried_hash(&self) -> Option<[u8; 32]> {
        self.last_queried_and_verified_hash.borrow_mut().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sov_mock_da::{verifier::MockShortHeaderProof, MockDaSpec};
    use std::collections::VecDeque;

    #[test]
    fn test_successful_short_header_proof_verification() {
        let block_hash = [1u8; 32];
        let prev_block_hash = [2u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 100;
        let coinbase_depth = 1;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: prev_block_hash,
            txs_commitment,
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        let mut proofs = VecDeque::new();
        proofs.push_back(proof_bytes);

        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                l1_height,
                txs_commitment,
                coinbase_depth,
                50,
            )
            .unwrap();

        assert!(ok);
        assert_eq!(service.take_last_queried_hash(), Some(block_hash));
    }

    #[test]
    fn test_first_block_verification() {
        let block_hash = [1u8; 32];
        let prev_block_hash = [0u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 1;
        let coinbase_depth = 1;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [4u8; 32],
            txs_commitment,
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        let mut proofs = VecDeque::new();
        proofs.push_back(proof_bytes);

        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                l1_height,
                txs_commitment,
                coinbase_depth,
                1,
            )
            .unwrap();

        assert!(ok);
        assert_eq!(service.take_last_queried_hash(), Some(block_hash));
    }

    #[test]
    fn test_invalid_proof_verification() {
        let block_hash = [1u8; 32];
        let prev_block_hash = [2u8; 32];
        let txs_commitment = [3u8; 32];
        let l1_height = 100;
        let coinbase_depth = 1;

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [5u8; 32],
            txs_commitment: [6u8; 32],
            height: l1_height,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        let mut proofs = VecDeque::new();
        proofs.push_back(proof_bytes);

        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

        let ok = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                l1_height + 1,
                txs_commitment,
                coinbase_depth,
                50,
            )
            .unwrap();

        assert!(!ok);
        assert_eq!(service.take_last_queried_hash(), None);
    }

    #[test]
    #[should_panic(expected = "Should have short header proof for l1 hash")]
    fn test_no_proof_available() {
        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(VecDeque::new());

        service
            .get_and_verify_short_header_proof_by_l1_hash(
                [1u8; 32],
                [2u8; 32],
                100,
                [3u8; 32],
                1,
                50,
            )
            .unwrap();
    }

    #[test]
    fn test_take_last_queried_hash() {
        let block_hash = [1u8; 32];
        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: [2u8; 32],
            txs_commitment: [3u8; 32],
            height: 100,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        let mut proofs = VecDeque::new();
        proofs.push_back(proof_bytes);

        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

        assert_eq!(service.take_last_queried_hash(), None);

        service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                [2u8; 32],
                100,
                [3u8; 32],
                1,
                50,
            )
            .unwrap();

        assert_eq!(service.take_last_queried_hash(), Some(block_hash));
        assert_eq!(service.take_last_queried_hash(), None);
    }

    #[test]
    fn test_multiple_proofs() {
        let block_hash1 = [1u8; 32];
        let block_hash2 = [2u8; 32];

        let mock_proof1 = MockShortHeaderProof {
            header_hash: block_hash1,
            prev_header_hash: [3u8; 32],
            txs_commitment: [4u8; 32],
            height: 100,
        };
        let mock_proof2 = MockShortHeaderProof {
            header_hash: block_hash2,
            prev_header_hash: block_hash1,
            txs_commitment: [5u8; 32],
            height: 101,
        };

        let mut proofs = VecDeque::new();
        proofs.push_back(borsh::to_vec(&mock_proof1).unwrap());
        proofs.push_back(borsh::to_vec(&mock_proof2).unwrap());

        let service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

        let ok1 = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash1,
                [3u8; 32],
                100,
                [4u8; 32],
                1,
                50,
            )
            .unwrap();
        assert!(ok1);
        assert_eq!(service.take_last_queried_hash(), Some(block_hash1));

        let ok2 = service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash2,
                block_hash1,
                101,
                [5u8; 32],
                1,
                51,
            )
            .unwrap();
        assert!(ok2);
        assert_eq!(service.take_last_queried_hash(), Some(block_hash2));
        assert_eq!(service.take_last_queried_hash(), None);
    }
}
