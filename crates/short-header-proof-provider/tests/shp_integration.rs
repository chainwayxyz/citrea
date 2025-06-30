#![cfg(feature = "native")]
use std::collections::VecDeque;

use short_header_proof_provider::{
    NativeShortHeaderProofProviderService, ShortHeaderProofProvider, ShortHeaderProofProviderError,
    ZkShortHeaderProofProviderService,
};
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::verifier::MockShortHeaderProof;
use sov_mock_da::MockDaSpec;
use tempfile::TempDir;

fn setup_test_db() -> (TempDir, sov_db::ledger_db::LedgerDB) {
    let temp_dir = TempDir::new().unwrap();
    let config = RocksdbConfig::new(temp_dir.path(), None, None);
    let ledger_db = sov_db::ledger_db::LedgerDB::with_config(&config).unwrap();
    (temp_dir, ledger_db)
}

#[test]
#[should_panic(expected = "Should have short header proof for l1 hash")]
fn test_proof_not_found() {
    let (_temp_dir, ledger_db) = setup_test_db();
    let native_service = NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db);

    let block_hash = [1u8; 32];
    let result = native_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash, [2u8; 32], 100, [3u8; 32], 1, 50);
    assert!(matches!(
        result.unwrap_err(),
        ShortHeaderProofProviderError::ShortHeaderProofNotFound
    ));

    // for zk this should panic
    let zk_service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(VecDeque::new());
    let _ = zk_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash, [2u8; 32], 100, [3u8; 32], 1, 50);
}

#[test]
fn test_native_clear_and_take_queried_hashes() {
    let (_temp_dir, ledger_db) = setup_test_db();
    let native_service =
        NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

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

    native_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash, [2u8; 32], 100, [3u8; 32], 1, 50)
        .unwrap();

    assert!(!native_service.queried_and_verified_hashes.lock().is_empty());

    native_service.clear_queried_hashes();

    assert!(native_service.queried_and_verified_hashes.lock().is_empty());

    // test with multiple hashes
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

    native_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash1, [3u8; 32], 100, [4u8; 32], 1, 50)
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

    native_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash2, [5u8; 32], 101, [6u8; 32], 1, 51)
        .unwrap();

    let hashes = native_service.take_queried_hashes(50..=51).unwrap();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&block_hash1));
    assert!(hashes.contains(&block_hash2));

    let hashes = native_service.take_queried_hashes(50..=50).unwrap();
    assert_eq!(hashes.len(), 1);
    assert!(hashes.contains(&block_hash1));
}

#[test]
fn test_zk_take_last_queried_hash() {
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

    let zk_service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs);

    assert_eq!(zk_service.take_last_queried_hash(), None);

    zk_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash, [2u8; 32], 100, [3u8; 32], 1, 50)
        .unwrap();

    assert_eq!(zk_service.take_last_queried_hash(), Some(block_hash));
    assert_eq!(zk_service.take_last_queried_hash(), None);
}

#[test]
fn test_native_to_zk_proof_flow() {
    let (_temp_dir, ledger_db) = setup_test_db();
    let native_service =
        NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

    let block_hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut proofs = Vec::new();

    // store proofs in native and collect them for zk
    for (i, &block_hash) in block_hashes.iter().enumerate() {
        let prev_block_hash = if i == 0 {
            [0u8; 32]
        } else {
            block_hashes[i - 1]
        };

        let mock_proof = MockShortHeaderProof {
            header_hash: block_hash,
            prev_header_hash: prev_block_hash,
            txs_commitment: [(i + 1) as u8; 32],
            height: i as u64 + 100,
        };
        let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
        proofs.push(proof_bytes.clone());

        ledger_db
            .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes)
            .unwrap();

        let ok = native_service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                i as u64 + 100,
                [(i + 1) as u8; 32],
                1,
                i as u64 + 50,
            )
            .unwrap();
        assert!(ok);
    }

    let verified_hashes = native_service.take_queried_hashes(50..=52).unwrap();
    assert_eq!(verified_hashes.len(), 3);
    assert_eq!(verified_hashes, block_hashes);

    let proofs_queue = VecDeque::from(proofs);
    let zk_service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs_queue);

    // verify the same sequence with zk
    for (i, &block_hash) in block_hashes.iter().enumerate() {
        let prev_block_hash = if i == 0 {
            [0u8; 32]
        } else {
            block_hashes[i - 1]
        };

        let ok = zk_service
            .get_and_verify_short_header_proof_by_l1_hash(
                block_hash,
                prev_block_hash,
                i as u64 + 100,
                [(i + 1) as u8; 32],
                1,
                i as u64 + 50,
            )
            .unwrap();
        assert!(ok);

        assert_eq!(zk_service.take_last_queried_hash(), Some(block_hash));
    }

    // zk consumed all proofs
    assert_eq!(zk_service.take_last_queried_hash(), None);
}

#[test]
fn test_native_to_zk_invalid_proof_flow() {
    let (_temp_dir, ledger_db) = setup_test_db();
    let native_service =
        NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

    // create and store an invalid proof
    let block_hash = [1u8; 32];
    let mock_proof = MockShortHeaderProof {
        header_hash: block_hash,
        prev_header_hash: [2u8; 32],
        txs_commitment: [3u8; 32],
        height: 100,
    };
    let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
    ledger_db
        .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes.clone())
        .unwrap();

    let ok = native_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [5u8; 32], // different prev_block_hash
            100, [3u8; 32], 1, 50,
        )
        .unwrap();
    assert!(!ok);

    let ok = native_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [2u8; 32], 101, // different height
            [3u8; 32], 1, 50,
        )
        .unwrap();
    assert!(!ok);

    let ok = native_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [2u8; 32], 100, [4u8; 32], // different txs commitment
            1, 50,
        )
        .unwrap();
    assert!(!ok);

    let verified_hashes = native_service.take_queried_hashes(50..=50).unwrap();
    assert!(verified_hashes.is_empty());

    let proofs_queue = VecDeque::from(vec![proof_bytes.clone(), proof_bytes.clone(), proof_bytes]);
    let zk_service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs_queue);

    let ok = zk_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [5u8; 32], // different prev_block_hash
            100, [3u8; 32], 1, 50,
        )
        .unwrap();
    assert!(!ok);

    let ok = zk_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [2u8; 32], 101, // different height
            [3u8; 32], 1, 50,
        )
        .unwrap();
    assert!(!ok);

    let ok = zk_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [2u8; 32], 100, [4u8; 32], // different txs commitment
            1, 50,
        )
        .unwrap();
    assert!(!ok);

    assert_eq!(zk_service.take_last_queried_hash(), None);
}

#[test]
fn test_native_to_zk_first_block_flow() {
    let (_temp_dir, ledger_db) = setup_test_db();
    let native_service =
        NativeShortHeaderProofProviderService::<MockDaSpec>::new(ledger_db.clone());

    let block_hash = [1u8; 32];
    let mock_proof = MockShortHeaderProof {
        header_hash: block_hash,
        prev_header_hash: [0u8; 32], // zero for first block
        txs_commitment: [3u8; 32],
        height: 1,
    };
    let proof_bytes = borsh::to_vec(&mock_proof).unwrap();
    ledger_db
        .put_short_header_proof_by_l1_hash(&block_hash, proof_bytes.clone())
        .unwrap();

    let ok = native_service
        .get_and_verify_short_header_proof_by_l1_hash(
            block_hash, [0u8; 32], // zero for first block
            1, [3u8; 32], 1, 1,
        )
        .unwrap();
    assert!(ok);

    let verified_hashes = native_service.take_queried_hashes(1..=1).unwrap();
    assert_eq!(verified_hashes, vec![block_hash]);

    let mut proofs_queue = VecDeque::new();
    proofs_queue.push_back(proof_bytes);
    let zk_service = ZkShortHeaderProofProviderService::<MockDaSpec>::new(proofs_queue);

    let ok = zk_service
        .get_and_verify_short_header_proof_by_l1_hash(block_hash, [0u8; 32], 1, [3u8; 32], 1, 1)
        .unwrap();
    assert!(ok);

    assert_eq!(zk_service.take_last_queried_hash(), Some(block_hash));
    assert_eq!(zk_service.take_last_queried_hash(), None);
}
