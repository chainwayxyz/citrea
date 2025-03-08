pub mod test_utils;

use sov_mock_da::{MockAddress, MockBlob, MockBlockHeader, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::MockZkGuest;
use sov_rollup_interface::da::{BlobReaderTrait, DataOnDa};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::BatchProofInfo;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;
use tempfile::tempdir;
use test_utils::{
    create_mock_batch_proof, create_new_method_id_tx, create_prev_lcp_serialized,
    create_random_state_diff, create_serialized_mock_proof, NativeCircuitRunner,
};

use crate::circuit::{LightClientProofCircuit, LightClientVerificationError};

type Height = u64;
const INITIAL_BATCH_PROOF_METHOD_IDS: [(Height, [u32; 8]); 1] = [(0, [0u32; 8])];

/// In the below tests, mock batch proofs are constructed with their last_l1_hash_on_bitcoin_light_client_contract field
/// having the same value with the L1 block these proofs are "found" on.
///
/// This is just to make testing easier as this is impossible on Bitcoin even if you are mining the block.

#[test]
fn test_light_client_circuit_valid_da_valid_data() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, true, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);

    // Now get more proofs to see the previous light client part is also working correctly
    let blob_3 = create_mock_batch_proof([3u8; 32], [4u8; 32], 4, true, block_header_1.hash.0);
    let blob_4 = create_mock_batch_proof([4u8; 32], [5u8; 32], 5, true, block_header_1.hash.0);

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(mock_output_1_serialized),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.l2_state_root, [5; 32]);
    assert!(output_2.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_2.last_l2_height, 5);
}

#[test]
fn test_wrong_order_da_blocks_should_still_work() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, true, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_2, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);
}

#[test]
fn create_unchainable_outputs_then_chain_them_on_next_block() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([3u8; 32], [4u8; 32], 4, true, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_2, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition has not happened because we are missing 1->2
    assert_eq!(output_1.l2_state_root, [1; 32]);
    // There would normally be 2 outputs here but since the order of the da data is => 3-4 and then 2-3 this is chained to one output => 2-4
    assert_eq!(output_1.unchained_batch_proofs_info.len(), 1);
    // Check to make sure
    assert_eq!(output_1.unchained_batch_proofs_info[0].last_l2_height, 4);
    // Init state root
    assert_eq!(
        output_1.unchained_batch_proofs_info[0].initial_state_root,
        [2; 32]
    );
    // Fin state root
    assert_eq!(
        output_1.unchained_batch_proofs_info[0].final_state_root,
        [4; 32]
    );

    // On the next l1 block, give 1-2 transition
    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_ser = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(mock_output_1_ser),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened from 1-4 now

    assert_eq!(output_2.l2_state_root, [4; 32]);
    assert!(output_2.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_2.last_l2_height, 4);
}

#[test]
fn test_header_chain_proof_height_and_hash() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, true, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);

    // Now give l1 block with height 3
    let blob_3 = create_mock_batch_proof([3u8; 32], [4u8; 32], 4, true, block_header_1.hash.0);
    let blob_4 = create_mock_batch_proof([4u8; 32], [5u8; 32], 5, true, block_header_1.hash.0);

    let block_header_2 = MockBlockHeader::from_height(3);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(prev_lcp_out),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    // Header chain verification must fail because the l1 block 3 was given before l1 block 2
    let res = zk_circuit_runner.run_circuit(
        da_verifier,
        input_2,
        ZkStorage::new(),
        Network::Nightly,
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );
    assert!(matches!(
        res,
        Err(LightClientVerificationError::HeaderChainVerificationFailed(
            _
        ))
    ));
}

#[test]
fn test_unverifiable_batch_proofs() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, false, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.unchained_batch_proofs_info.len(), 0);
}

#[test]
#[should_panic = "Assumption proof verification failed!"]
fn test_unverifiable_prev_light_client_proof() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, false, block_header_1.hash.0);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.unchained_batch_proofs_info.len(), 0);

    let block_header_2 = MockBlockHeader::from_height(2);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, false);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(prev_lcp_out),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let _ = zk_circuit_runner
        .run_circuit(
            da_verifier,
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();
}

#[test]
fn test_new_method_id_txs() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_new_method_id_tx(10, [2u32; 8], method_id_upgrade_authority);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output_1.batch_proof_method_ids.len(), 2);
    assert_eq!(
        output_1.batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );

    // now try wrong method id
    let blob_2 = create_new_method_id_tx(10, [3u32; 8], batch_prover_da_pub_key);

    let block_header_2 = MockBlockHeader::from_height(2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // didn't change
    assert_eq!(output_2.batch_proof_method_ids.len(), 2);
    assert_eq!(
        output_2.batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );

    // now try activation height < last activationg height and activation height = last activation height
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_upgrade_authority);
    let blob_2 = create_new_method_id_tx(3, [2u32; 8], method_id_upgrade_authority);

    let block_header_3 = MockBlockHeader::from_height(3);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(create_prev_lcp_serialized(output_2, true)),
            light_client_proof_method_id,
            da_block_header: block_header_3,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_3 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    // didn't change
    assert_eq!(output_3.batch_proof_method_ids.len(), 2);
    assert_eq!(
        output_3.batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );
}

#[test]
fn test_unverifiable_batch_proof_is_ignored() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 2, false, block_header_1.hash.0);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, [2; 32]);
    assert_eq!(output.unchained_batch_proofs_info.len(), 0);
}

#[test]
fn test_light_client_circuit_verify_chunks() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let state_diff = create_random_state_diff(100);

    let block_header_1 = MockBlockHeader::from_height(1);

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        [2u8; 32],
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
    );

    let chunk1 = serialized_mock_proof[0..39700].to_vec();
    let chunk1_da_data = DataOnDa::Chunk(chunk1.clone());
    let chunk1_serialized = borsh::to_vec(&chunk1_da_data).expect("should serialize");

    let blob1 = MockBlob::new(
        chunk1_serialized.clone(),
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([1; 32]),
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([2; 32]),
    );

    blob2.full_data();

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([3; 32]),
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([4; 32]),
    );
    blob4.full_data();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob1, blob2, blob3, blob4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, [2; 32]);
}

#[test]
fn test_missing_chunk() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let state_diff = create_random_state_diff(100);

    let block_header_1 = MockBlockHeader::from_height(1);

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        [2u8; 32],
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
    );

    let chunk1 = serialized_mock_proof[0..39700].to_vec();
    let chunk1_da_data = DataOnDa::Chunk(chunk1.clone());
    let chunk1_serialized = borsh::to_vec(&chunk1_da_data).expect("should serialize");

    let blob1 = MockBlob::new(
        chunk1_serialized.clone(),
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([1; 32]),
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([2; 32]),
    );

    blob2.full_data();

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([3; 32]),
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([4; 32]),
    );
    blob4.full_data();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            // Blob2 is not present
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob1, blob3, blob4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
}

#[test]
fn test_malicious_aggregate_should_not_work() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let method_id_upgrade_authority = [11u8; 32];
    let block_header_1 = MockBlockHeader::from_height(1);

    let state_diff = create_random_state_diff(100);

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        [2u8; 32],
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
    );

    let chunk1 = serialized_mock_proof[0..39700].to_vec();
    let chunk1_da_data = DataOnDa::Chunk(chunk1.clone());
    let chunk1_serialized = borsh::to_vec(&chunk1_da_data).expect("should serialize");

    let blob1 = MockBlob::new(
        chunk1_serialized.clone(),
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([1; 32]),
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([2; 32]),
    );

    blob2.full_data();

    // First block has the two chunks
    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob1.clone(), blob2.clone()],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert!(output.unchained_batch_proofs_info.is_empty());

    let malicious_aggregate_da_data = DataOnDa::Aggregate(
        vec![blob1.wtxid().unwrap(), blob2.wtxid().unwrap()],
        vec![blob1.wtxid().unwrap(), blob2.wtxid().unwrap()],
    );
    let malicious_aggregate_serialized =
        borsh::to_vec(&malicious_aggregate_da_data).expect("should serialize");

    // Malicious blob sent, takes 2/3 of the chunks and tries to break the circuit
    let malicious_blob = MockBlob::new(
        malicious_aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([99; 32]),
    );
    malicious_blob.full_data();

    let block_header_2 = MockBlockHeader::from_height(2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(create_prev_lcp_serialized(output, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![malicious_blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    // The malicious did not work no state updates or panics
    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert!(output.unchained_batch_proofs_info.is_empty());

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    // Last chhunk
    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([3; 32]),
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
        vec![
            blob1.wtxid().unwrap(),
            blob2.wtxid().unwrap(),
            blob3.wtxid().unwrap(),
        ],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        Some([4; 32]),
    );
    blob4.full_data();

    let block_header_3 = MockBlockHeader::from_height(3);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(create_prev_lcp_serialized(output, true)),
            light_client_proof_method_id,
            da_block_header: block_header_3,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob3, blob4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &method_id_upgrade_authority,
        )
        .unwrap();

    // When last chunk is sent with the correct aggregate we can see the state update
    assert_eq!(output.l2_state_root, [2; 32]);
    assert_eq!(output.last_l2_height, 101);
    assert!(output.unchained_batch_proofs_info.is_empty());
}

#[test]
fn test_unknown_block_hash_in_batch_proof_not_verified() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_batch_proof([1u8; 32], [2u8; 32], 2, true, block_header_1.hash.0);
    let incorrect_hash = {
        let mut copy = block_header_1.hash.0;

        copy[0] = copy[0].wrapping_add(1);
        copy
    };
    let blob_2 = create_mock_batch_proof([2u8; 32], [3u8; 32], 3, true, incorrect_hash);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32].to_vec();
    let method_id_upgrade_authority = [11u8; 32].to_vec();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_1 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 2);

    let incorrect_hash = {
        let mut copy = block_header_1.hash.0;

        copy[0] = copy[0].wrapping_add(1);
        copy
    };
    // Now get more proofs to see the previous light client part is also working correctly
    let blob_3 = create_mock_batch_proof([3u8; 32], [4u8; 32], 4, true, incorrect_hash);
    let blob_4 = create_mock_batch_proof([4u8; 32], [5u8; 32], 5, true, block_header_1.hash.0);

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof_journal: Some(mock_output_1_serialized),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &method_id_upgrade_authority,
    );

    let output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.l2_state_root, [2; 32]);
    assert_eq!(
        output_2.unchained_batch_proofs_info,
        vec![BatchProofInfo {
            initial_state_root: [4u8; 32],
            final_state_root: [5u8; 32],
            last_l2_height: 5,
        }],
    );
    assert_eq!(output_2.last_l2_height, 2);
}
