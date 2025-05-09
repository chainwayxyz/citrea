pub mod test_utils;

use sov_mock_da::{MockAddress, MockBlob, MockBlockHeader, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::MockZkGuest;
use sov_modules_api::WorkingSet;
use sov_rollup_interface::da::{BlobReaderTrait, DataOnDa, SequencerCommitment};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::Network;
use sov_state::{ProverStorage, ZkStorage};
use tempfile::tempdir;
use test_utils::{
    create_mock_batch_proof, create_mock_sequencer_commitment,
    create_mock_sequencer_commitment_blob, create_new_method_id_tx, create_prev_lcp_serialized,
    create_random_state_diff, create_serialized_mock_proof, NativeCircuitRunner,
};

use crate::circuit::accessors::{
    BatchProofMethodIdAccessor, SequencerCommitmentAccessor,
    VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
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

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
    assert_eq!(output_1.last_l2_height, 3);

    let seq_comm_3 = create_mock_sequencer_commitment(3, 4, [4u8; 32]);
    let seq_comm_4 = create_mock_sequencer_commitment(4, 5, [5u8; 32]);

    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());
    let seq_comm_4_blob = create_mock_sequencer_commitment_blob(seq_comm_4.clone());

    // Now get more proofs to see the previous light client part is also working correctly
    let blob_3 = create_mock_batch_proof(
        [3u8; 32],
        4,
        true,
        block_header_1.hash.0,
        vec![seq_comm_3.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    let blob_4 = create_mock_batch_proof(
        [4u8; 32],
        5,
        true,
        block_header_1.hash.0,
        vec![seq_comm_4.clone()],
        Some(seq_comm_3.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_3_blob, seq_comm_4_blob, blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.l2_state_root, [5; 32]);
    assert_eq!(output_2.last_l2_height, 5);
}

// This will test a scenario like where we will have two batch proofs one of them will have commitments with indexes 1,2,3 the other will have 3,4,5
// And at the end we will see our last index and state root is commitment with index 5
#[test]
fn test_light_client_circuit_commitment_chaining() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);
    let seq_comm_3 = create_mock_sequencer_commitment(3, 4, [4u8; 32]);
    let seq_comm_4 = create_mock_sequencer_commitment(4, 5, [5u8; 32]);
    let seq_comm_5 = create_mock_sequencer_commitment(5, 6, [6u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());
    let seq_comm_4_blob = create_mock_sequencer_commitment_blob(seq_comm_4.clone());
    let seq_comm_5_blob = create_mock_sequencer_commitment_blob(seq_comm_5.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        4,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone(), seq_comm_2.clone(), seq_comm_3.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [4u8; 32],
        6,
        true,
        block_header_1.hash.0,
        vec![seq_comm_3.clone(), seq_comm_4.clone(), seq_comm_5.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![
                seq_comm_1_blob,
                seq_comm_2_blob,
                seq_comm_3_blob,
                seq_comm_4_blob,
                seq_comm_5_blob,
                blob_1,
                blob_2,
            ],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [6; 32]);
    assert_eq!(output_1.last_l2_height, 6);
}

#[test]
fn test_previous_commitment_not_set_should_not_transition() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        // The previous commitment not set so it will not transition to [3]
        None,
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_2_blob, seq_comm_1_blob, blob_2, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
}

#[test]
fn test_batch_proof_with_missing_commitment_not_set_should_not_transition() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, l2_genesis_state_root);
    assert_eq!(output_1.last_l2_height, 0);
}

#[test]
fn test_wrong_order_da_blocks_should_still_work() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_2_blob, seq_comm_1_blob, blob_2, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
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

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);
    let seq_comm_3 = create_mock_sequencer_commitment(3, 4, [4u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [3u8; 32],
        4,
        true,
        block_header_1.hash.0,
        vec![seq_comm_3.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![
                seq_comm_1_blob,
                seq_comm_2_blob,
                seq_comm_3_blob,
                blob_2,
                blob_1,
            ],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition has not happened because we are missing 1->2
    assert_eq!(output_1.l2_state_root, [1; 32]);
    assert_eq!(output_1.last_l2_height, 0);
    assert_eq!(output_1.last_sequencer_commitment_index, 0);

    let storage = native_circuit_runner
        .prover_storage_manager
        .create_final_view_storage();

    let mut working_set = WorkingSet::new(storage.clone());

    let unchained_info2 =
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
            2,
            &mut working_set,
        )
        .unwrap();
    assert_eq!(unchained_info2.initial_state_root, seq_comm_1.merkle_root);
    assert_eq!(
        unchained_info2.last_l2_height,
        seq_comm_2.l2_end_block_number
    );
    let unchained_info3 =
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
            3,
            &mut working_set,
        )
        .unwrap();
    assert_eq!(unchained_info3.initial_state_root, seq_comm_2.merkle_root);
    assert_eq!(
        unchained_info3.last_l2_height,
        seq_comm_3.l2_end_block_number
    );

    // On the next l1 block, give 1-2 transition
    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1],
        None,
        batch_prover_da_pub_key,
    );

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_ser = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_ser),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened from 1-4 now
    assert_eq!(output_2.l2_state_root, [4; 32]);
    assert_eq!(output_2.last_l2_height, 4);
    assert_eq!(output_2.last_sequencer_commitment_index, 3);
}

#[test]
fn test_header_chain_proof_height_and_hash() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [3; 32]);
    assert_eq!(output_1.last_l2_height, 3);
    assert_eq!(output_1.last_sequencer_commitment_index, 2);

    let seq_comm_3 = create_mock_sequencer_commitment(3, 4, [4u8; 32]);
    let seq_comm_4 = create_mock_sequencer_commitment(4, 5, [5u8; 32]);

    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());
    let seq_comm_4_blob = create_mock_sequencer_commitment_blob(seq_comm_4.clone());

    // Now give l1 block with height 3
    let blob_3 = create_mock_batch_proof(
        [3u8; 32],
        4,
        true,
        block_header_1.hash.0,
        vec![seq_comm_3.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    let blob_4 = create_mock_batch_proof(
        [4u8; 32],
        5,
        true,
        block_header_1.hash.0,
        vec![seq_comm_4],
        Some(seq_comm_3.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let block_header_2 = MockBlockHeader::from_height(3);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(prev_lcp_out),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_4_blob, seq_comm_3_blob, blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
        &sequencer_da_pub_key,
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

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    // ZK proof invalid
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        false,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    // Wrong pubkey
    let blob_3 = create_mock_batch_proof(
        [2u8; 32],
        3,
        false,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        [1u8; 32], // wrong pubkey
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1, blob_2, blob_3],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert!(
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
            2,
            &mut working_set
        )
        .is_none()
    );
}

#[test]
#[should_panic = "Previous light client proof is invalid"]
fn test_unverifiable_prev_light_client_proof() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        false,
        block_header_1.hash.0,
        vec![seq_comm_2],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert!(
        VerifiedStateTransitionForSequencerCommitmentIndexAccessor::<ProverStorage>::get(
            2,
            &mut working_set
        )
        .is_none()
    );

    let block_header_2 = MockBlockHeader::from_height(2);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, false);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(prev_lcp_out),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
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
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1],
        None,
        batch_prover_da_pub_key,
    );
    let blob_2 = create_new_method_id_tx(10, [2u32; 8], method_id_upgrade_authority);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(batch_proof_method_ids.len(), 2);
    assert_eq!(
        batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );

    // now try wrong method id
    let blob_2 = create_new_method_id_tx(10, [3u32; 8], batch_prover_da_pub_key);

    let block_header_2 = MockBlockHeader::from_height(2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();

    // didn't change
    assert_eq!(batch_proof_method_ids.len(), 2);
    assert_eq!(
        batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );

    // now try activation height < last activationg height and activation height = last activation height
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_upgrade_authority);
    let blob_2 = create_new_method_id_tx(3, [2u32; 8], method_id_upgrade_authority);

    let block_header_3 = MockBlockHeader::from_height(3);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_2, true)),
            light_client_proof_method_id,
            da_block_header: block_header_3,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        &method_id_upgrade_authority,
    );

    let _output_3 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();

    // didn't change
    assert_eq!(batch_proof_method_ids.len(), 2);
    assert_eq!(
        batch_proof_method_ids,
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
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        2,
        false,
        block_header_1.hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, [2; 32]);
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
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let state_diff = create_random_state_diff(100);

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 41, [99u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 61, [98u8; 32]);
    let seq_comm_3 = create_mock_sequencer_commitment(3, 101, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
        vec![seq_comm_1.clone(), seq_comm_2.clone(), seq_comm_3.clone()],
        None,
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
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![
                seq_comm_1_blob,
                seq_comm_2_blob,
                seq_comm_3_blob,
                blob1,
                blob2,
                blob3,
                blob4,
            ],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
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
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let state_diff = create_random_state_diff(100);

    let block_header_1 = MockBlockHeader::from_height(1);
    let seq_comm_1 = create_mock_sequencer_commitment(1, 101, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
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
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            // Blob2 is not present
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, blob1, blob3, blob4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);
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
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let state_diff = create_random_state_diff(100);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 101, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());

    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
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
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, blob1.clone(), blob2.clone()],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);

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
            previous_light_client_proof: Some(create_prev_lcp_serialized(output, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![malicious_blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // The malicious did not work no state updates or panics
    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);

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
            previous_light_client_proof: Some(create_prev_lcp_serialized(output, true)),
            light_client_proof_method_id,
            da_block_header: block_header_3,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob3, blob4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // When last chunk is sent with the correct aggregate we can see the state update
    assert_eq!(output.l2_state_root, [2; 32]);
    assert_eq!(output.last_l2_height, 101);
    assert_eq!(output.last_sequencer_commitment_index, 1);
}

#[test]
fn test_unknown_block_hash_in_batch_proof_not_verified() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());

    let batch_prover_da_pub_key = [9; 32];

    let blob_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        block_header_1.hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let incorrect_hash = {
        let mut copy = block_header_1.hash.0;

        copy[0] = copy[0].wrapping_add(1);
        copy
    };

    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        incorrect_hash,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_2_blob, seq_comm_1_blob, blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);

    let incorrect_hash = {
        let mut copy = block_header_1.hash.0;

        copy[0] = copy[0].wrapping_add(1);
        copy
    };

    let seq_comm_3 = create_mock_sequencer_commitment(3, 4, [4u8; 32]);
    let seq_comm_4 = create_mock_sequencer_commitment(4, 5, [5u8; 32]);

    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());
    let seq_comm_4_blob = create_mock_sequencer_commitment_blob(seq_comm_4.clone());

    // Now get more proofs to see the previous light client part is also working correctly
    let blob_3 = create_mock_batch_proof(
        [3u8; 32],
        4,
        true,
        incorrect_hash,
        vec![seq_comm_3.clone()],
        Some(seq_comm_2.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );
    let blob_4 = create_mock_batch_proof(
        [4u8; 32],
        5,
        true,
        block_header_1.hash.0,
        vec![seq_comm_4.clone()],
        Some(seq_comm_3.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized),
            da_block_header: block_header_2,
            light_client_proof_method_id,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_3_blob, seq_comm_4_blob, blob_3, blob_4],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.l2_state_root, [2; 32]);

    assert_eq!(output_2.last_l2_height, 2);
    assert_eq!(output_2.last_sequencer_commitment_index, 1);
}

#[test]
fn test_light_client_circuit_verify_sequencer_commitment() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let commitment = SequencerCommitment {
        merkle_root: [1; 32],
        index: 1,
        l2_end_block_number: 30,
    };
    let commitment_da_data = DataOnDa::SequencerCommitment(commitment);
    let commitment_serialized = borsh::to_vec(&commitment_da_data).expect("should serialize");

    let blob1 = MockBlob::new(
        commitment_serialized.clone(),
        MockAddress::new(sequencer_da_pub_key),
        [0u8; 32],
        Some([1; 32]),
    );
    blob1.full_data();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    let block_header_2 = MockBlockHeader::from_height(2);
    let mock_output_1_serialized = create_prev_lcp_serialized(output, true);

    // resubmit the same comment with same index but different params
    let commitment = SequencerCommitment {
        merkle_root: [2; 32],
        index: 1,
        l2_end_block_number: 60,
    };
    let commitment_da_data = DataOnDa::SequencerCommitment(commitment);
    let commitment_serialized = borsh::to_vec(&commitment_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        commitment_serialized.clone(),
        MockAddress::new(sequencer_da_pub_key),
        [1u8; 32],
        Some([2; 32]),
    );
    blob2.full_data();

    let input2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        &method_id_upgrade_authority,
    );

    zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    let prover_storage = native_circuit_runner
        .prover_storage_manager
        .create_final_view_storage();
    let mut working_set = WorkingSet::new(prover_storage);
    let commitment =
        SequencerCommitmentAccessor::get(1, &mut working_set).expect("Should be available");

    // Make sure that the original commitment with index 1 was not
    // overwritten by the second block's commitment
    assert_eq!(commitment.index, 1);
    assert_eq!(commitment.l2_end_block_number, 30);
    assert_eq!(commitment.merkle_root, [1; 32]);
}

#[test]
fn wrong_pubkey_sequencer_commitment_should_not_work() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_upgrade_authority = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let commitment = SequencerCommitment {
        merkle_root: [1; 32],
        index: 1,
        l2_end_block_number: 30,
    };
    let commitment_da_data = DataOnDa::SequencerCommitment(commitment);
    let commitment_serialized = borsh::to_vec(&commitment_da_data).expect("should serialize");

    let blob1 = MockBlob::new(
        commitment_serialized.clone(),
        MockAddress::new(sequencer_da_pub_key),
        [0u8; 32],
        Some([1; 32]),
    );
    blob1.full_data();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
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
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    let block_header_2 = MockBlockHeader::from_height(2);
    let mock_output_1_serialized = create_prev_lcp_serialized(output, true);

    // submit next commitment from wrong pubkey
    let commitment = SequencerCommitment {
        merkle_root: [2; 32],
        index: 1,
        l2_end_block_number: 60,
    };
    let commitment_da_data = DataOnDa::SequencerCommitment(commitment);
    let commitment_serialized = borsh::to_vec(&commitment_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        commitment_serialized.clone(),
        MockAddress::new([54u8; 32]),
        [1u8; 32],
        Some([2; 32]),
    );
    blob2.full_data();

    let input2: LightClientCircuitInput<MockDaSpec> = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        &method_id_upgrade_authority,
    );

    zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key.clone(),
            &sequencer_da_pub_key,
            &method_id_upgrade_authority,
        )
        .unwrap();

    let prover_storage = native_circuit_runner
        .prover_storage_manager
        .create_final_view_storage();
    let mut working_set = WorkingSet::new(prover_storage);
    let commitment =
        SequencerCommitmentAccessor::get(1, &mut working_set).expect("Should be available");

    // As the first commitment pubkey was correct, this was set
    assert_eq!(commitment.index, 1);
    assert_eq!(commitment.l2_end_block_number, 30);
    assert_eq!(commitment.merkle_root, [1; 32]);

    let commitment = SequencerCommitmentAccessor::get(2, &mut working_set);

    // ignored commitment from wrong pubkey
    assert_eq!(commitment, None);
}
