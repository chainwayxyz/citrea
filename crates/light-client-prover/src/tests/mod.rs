pub mod test_utils;

use sov_mock_da::{MockAddress, MockBlob, MockBlockHeader, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::MockZkGuest;
use sov_modules_api::WorkingSet;
use sov_modules_core::StorageValue;
use sov_rollup_interface::da::{
    BlobReaderTrait, DataOnDa, SequencerCommitment, MAX_THRESHOLD_PROXIMITY, MIN_THRESHOLD,
};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    LightClientCircuitOutput, VerifiedStateTransitionForSequencerCommitmentIndex,
};
use sov_rollup_interface::Network;
use sov_state::{ProverStorage, ZkStorage};
use tempfile::tempdir;
use test_utils::{
    create_add_member_tx, create_mock_batch_proof, create_mock_sequencer_commitment,
    create_mock_sequencer_commitment_blob, create_new_method_id_tx, create_prev_lcp_serialized,
    create_random_state_diff, create_remove_member_tx, create_remove_method_id_tx,
    create_replace_member_tx, create_serialized_mock_proof, create_set_lcp_to_previous_state_tx,
    create_update_batch_prover_pub_key_tx,
    create_update_batch_prover_pub_key_tx_with_signing_chain_id,
    create_update_sequencer_pub_key_tx, create_update_sequencer_pub_key_tx_with_signing_chain_id,
    create_update_threshold_tx, NativeCircuitRunner,
};

use crate::circuit::accessors::{
    BatchProofMethodIdAccessor, BatchProverDaPubKeyAccessor, RevertEpochAccessor,
    SecurityCouncilAddressAccessor, SecurityCouncilNonceAccessor, SecurityCouncilThresholdAccessor,
    SequencerCommitmentAccessor, SequencerDaPubKeyAccessor,
    VerifiedStateTransitionForSequencerCommitmentIndexAccessor,
};
use crate::circuit::initial_values::mockda::{
    EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME, INITIAL_SECURITY_COUNCIL_THRESHOLD,
    SECURITY_COUNCIL_INITIAL_DA_ADDRESSES,
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
        &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
    let method_id_sender = [11u8; 32];

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
    let blob_2 = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);

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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
    let blob_2 =
        create_new_method_id_tx(10, [3u32; 8], batch_prover_da_pub_key, Network::Nightly, 2);

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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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

    // now try activation height < last activating height and activation height = last activation height
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 2);
    let blob_2 = create_new_method_id_tx(3, [2u32; 8], method_id_sender, Network::Nightly, 2);

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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
fn test_wrong_network_method_id_update_should_fail() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // Create method id update for a different network
    let blob = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Mainnet, 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _ = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
    assert_eq!(batch_proof_method_ids.len(), 1);
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [1; 32],
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [2; 32],
    );

    blob2.full_data();

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [3; 32],
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [4; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [1; 32],
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [2; 32],
    );

    blob2.full_data();

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [3; 32],
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [4; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);
}

#[test]
fn test_light_client_circuit_aggregate_size_overflow() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let seq_comm_1 = create_mock_sequencer_commitment(1, 41, [99u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 61, [98u8; 32]);
    let seq_comm_3 = create_mock_sequencer_commitment(3, 101, [2u8; 32]);

    let seq_comm_1_blob = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let seq_comm_2_blob = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let seq_comm_3_blob = create_mock_sequencer_commitment_blob(seq_comm_3.clone());

    let state_diff = create_random_state_diff(1100);
    let serialized_mock_proof = create_serialized_mock_proof(
        l2_genesis_state_root,
        101,
        true,
        Some(state_diff),
        block_header_1.hash.0,
        vec![seq_comm_1.clone(), seq_comm_2.clone(), seq_comm_3.clone()],
        None,
    );

    let mut chunk_blobs = vec![];

    for (i, chunk) in serialized_mock_proof.chunks(39700).enumerate() {
        let chunk_da_data = DataOnDa::Chunk(chunk.to_vec());
        let chunk_serialized = borsh::to_vec(&chunk_da_data).expect("should serialize");

        let blob = MockBlob::new(
            chunk_serialized,
            MockAddress::new([9u8; 32]),
            [0u8; 32],
            [(i + 1) as u8; 32],
        );
        blob.full_data();
        chunk_blobs.push(blob);
    }

    let chunk_wtxids: Vec<[u8; 32]> = chunk_blobs.iter().map(|b| b.wtxid()).collect();

    let aggregate_da_data = DataOnDa::Aggregate(chunk_wtxids.clone(), chunk_wtxids);

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob_aggregate = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [4; 32],
    );
    blob_aggregate.full_data();

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: [seq_comm_1_blob, seq_comm_2_blob, seq_comm_3_blob]
                .into_iter()
                .chain(chunk_blobs)
                .chain([blob_aggregate])
                .collect(),
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // aggregate too large, should not be processed
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
        [1; 32],
    );
    blob1.full_data();

    let chunk2 = serialized_mock_proof[39700..39700 * 2].to_vec();
    let chunk2_da_data = DataOnDa::Chunk(chunk2.clone());
    let chunk2_serialized = borsh::to_vec(&chunk2_da_data).expect("should serialize");

    let blob2 = MockBlob::new(
        chunk2_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [2; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);

    let malicious_aggregate_da_data = DataOnDa::Aggregate(
        vec![blob1.wtxid(), blob2.wtxid()],
        vec![blob1.wtxid(), blob2.wtxid()],
    );
    let malicious_aggregate_serialized =
        borsh::to_vec(&malicious_aggregate_da_data).expect("should serialize");

    // Malicious blob sent, takes 2/3 of the chunks and tries to break the circuit
    let malicious_blob = MockBlob::new(
        malicious_aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [99; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // The malicious did not work no state updates or panics
    assert_eq!(output.l2_state_root, l2_genesis_state_root);
    assert_eq!(output.last_l2_height, 0);
    assert_eq!(output.last_sequencer_commitment_index, 0);

    let chunk3 = serialized_mock_proof[39700 * 2..].to_vec();
    let chunk3_da_data = DataOnDa::Chunk(chunk3.clone());
    let chunk3_serialized = borsh::to_vec(&chunk3_da_data).expect("should serialize");

    // Last chunk
    let blob3 = MockBlob::new(
        chunk3_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [3; 32],
    );
    blob3.full_data();

    let aggregate_da_data = DataOnDa::Aggregate(
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
        vec![blob1.wtxid(), blob2.wtxid(), blob3.wtxid()],
    );

    let aggregate_serialized = borsh::to_vec(&aggregate_da_data).expect("should serialize");

    let blob4 = MockBlob::new(
        aggregate_serialized,
        MockAddress::new([9u8; 32]),
        [0u8; 32],
        [4; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [1; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [2; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [1; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
        [2; 32],
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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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

// If we accept the fact that JMT is not tamperable, we can
// we only need to check for two scenarios:
// - If the circuit is inputted from a different tree, we must catch it.
// - If the value is tampered we must catch it.
#[should_panic = "jellyfish merkle tree update must succeed"]
#[test]
fn test_lcp_input_values_cant_be_tampered() {
    // set up the test environment with
    // a few sequencer commitments
    // and batch proofs that will only process the first sequencer commitment
    // is enough
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

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // sanity check
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);

    // environment is set up

    // then we'll make a new run creating an input for correct run
    let block_header_2 = MockBlockHeader::from_height(2);

    let mut input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2.clone(),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    // at this point returned witness will look like this:
    // <BatchProverDaPubKeyAccessor::get() val>          index 0
    // <SequencerDaPubKeyAccessor::get() val>            index 1
    // <RevertEpochAccessor::get_or_default() val>       index 2
    // <VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(2) val>  index 3
    // <prev root>                                       index 4
    // <BatchProverDaPubKeyAccessor read proof>          index 5
    // <SequencerDaPubKeyAccessor read proof>            index 6
    // <RevertEpochAccessor read proof>                  index 7
    // <VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(2) read proof>  index 8
    // <jmt update proof> (includes inserting blockhash) index 9
    // <final root>                                      index 10
    // let's try changing the value of VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(2)
    // as it was None, we'll try cheating and setting it to Some(VerifiedStateTransitionForSequencerCommitmentIndex{})
    // this simulates a light client prover that tries to move state of the L2 without a valid batch proof found on DA

    let mut witness = input.witness.get_hints();

    // values are pushed into the witness as so:
    // borsh::to_vec(Option<StorageValue>)

    let storage_value: StorageValue =
        borsh::to_vec(&VerifiedStateTransitionForSequencerCommitmentIndex {
            initial_state_root: [2; 32],
            final_state_root: [3; 32],
            last_l2_height: 3,
        })
        .unwrap()
        .into();

    // Index 3 is the VerifiedStateTransitionForSequencerCommitmentIndex value
    // (indices 0 and 1 are BatchProverDaPubKey and SequencerDaPubKey values, index 2 is RevertEpoch)
    witness[3] = borsh::to_vec(&Some(storage_value)).unwrap();

    // Since we tampered index 3 to Some, the circuit will now also read:
    // - VerifiedStateTransitionEpochAccessor::get_or_default(2) (None → returns default 0, matching current epoch)
    // - VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(3) (None, stops the loop)
    // Insert these two value hints after the tampered value
    witness.insert(4, vec![0]); // VerifiedStateTransitionEpochAccessor::get_or_default(2) = None/default
    witness.insert(5, vec![0]); // VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(3) = None

    // After inserting 2 value hints, the proof section has shifted by +2:
    // index 6: prev root
    // index 7: BatchProverDaPubKey read proof
    // index 8: SequencerDaPubKey read proof
    // index 9: RevertEpoch read proof
    // index 10: VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(2) read proof

    // reusing get(2) read proof for VerifiedStateTransitionEpoch(2) and get(3) absence proofs
    // as get(2) value mismatch will cause the panic before these proofs are verified
    witness.insert(11, witness[10].clone()); // VerifiedStateTransitionEpochAccessor::get_or_default(2) read proof
    witness.insert(12, witness[10].clone()); // VerifiedStateTransitionForSequencerCommitmentIndexAccessor::get(3) read proof

    input.witness = witness.into();

    // we are not concerned with trying to forge a JMT read proof for now-existing VerifiedStateTransitionForSequencerCommitmentIndexAccessor(2)
    // it's impossible for the current tree
    // or we would add it to the tree, which would then fail because the expected root would be different
    // trying to forge a JMT update proof for this test case is unnecessary as it means testing JMT itself.

    zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();
}

// now we'll try to make a new tree that contains the same data except for L1 hashes
// and then try to replace the prev root with a different one
// with valid read and update proofs
// essentially trying to hack the circuit by providing values and proofs from a different tree
// we make it similar so the circuit won't panic but will follow until the storage verification part
#[should_panic = "Witness prev root is wrong!"]
#[test]
fn test_lcp_cant_be_passed_roots_from_a_different_tree() {
    // set up the test environment with
    // a few sequencer commitments
    // and batch proofs that will only process the first sequencer commitment
    // is enough
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

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, seq_comm_2_blob, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // sanity check
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);

    // environment is set up

    // let's move to a different tree by inserting a random data
    native_circuit_runner.insert_random_chunk();

    // we'll use hints from here for the next block
    // if we can make the circuit accept this new tree
    // that means we can do anything with the circuit

    let block_header_2 = MockBlockHeader::from_height(2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2.clone(),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();
}

#[test]
fn test_add_security_council_member() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_member = [99u8; 20];
    let blob = create_add_member_tx(new_member, 3, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 6); // 5 initial + 1 new
    assert_eq!(addresses.last().unwrap().0 .0, new_member);

    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, 3);
}

#[test]
fn test_add_duplicate_member_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let initial_addresses = SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner();
    let existing_member = initial_addresses[0].0 .0;

    let blob = create_add_member_tx(existing_member, 3, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        initial_addresses,
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            initial_addresses,
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 5);
}

#[test]
fn test_remove_security_council_member() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let initial_addresses = SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner();
    let member_to_remove = initial_addresses[4].0 .0;

    let blob = create_remove_member_tx(member_to_remove, 2, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        initial_addresses,
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            initial_addresses,
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 4);
    assert!(!addresses.iter().any(|a| a.0 .0 == member_to_remove));

    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, 2);
}

#[test]
fn test_remove_nonexistent_member_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let nonexistent_member = [88u8; 20];
    let blob = create_remove_member_tx(nonexistent_member, 3, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 5);
}

#[test]
fn test_update_security_council_threshold() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob = create_update_threshold_tx(2, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, 2);
}

#[test]
fn test_invalid_threshold_update_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // threshold 6 > 5 members, should be rejected
    let blob = create_update_threshold_tx(6, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD);
}

#[test]
fn test_replace_security_council_member() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let initial_addresses = SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner();
    let old_member = initial_addresses[4].0 .0;
    let new_member = [77u8; 20];

    let blob = create_replace_member_tx(old_member, new_member, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        initial_addresses,
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            initial_addresses,
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 5);
    assert!(!addresses.iter().any(|a| a.0 .0 == old_member));
    assert!(addresses.iter().any(|a| a.0 .0 == new_member));

    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD);
}

#[test]
fn test_add_member_exceeds_max_count_rejected() {
    use alloy_primitives::Address;

    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // Build 10 initial members: 5 from known keys + 5 random
    let known_addresses = SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner();
    let mut initial_addresses: Vec<Address> = known_addresses.to_vec();
    for i in 0u8..5 {
        initial_addresses.push(Address::from_slice(&[50 + i; 20]));
    }
    assert_eq!(initial_addresses.len(), 10);

    let new_member = [99u8; 20];
    // threshold 3 is valid for 10 members (3 >= MIN_THRESHOLD=2, 3 <= 10-2=8)
    let threshold = 3u32;
    let member_count = initial_addresses.len();
    assert!(threshold as usize >= MIN_THRESHOLD);
    assert!(threshold as usize <= member_count - MAX_THRESHOLD_PROXIMITY);
    let blob = create_add_member_tx(new_member, threshold, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        &initial_addresses,
        threshold as usize,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            &initial_addresses,
            threshold as usize,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 10); // Still 10, add was rejected
}

#[test]
fn test_remove_member_below_min_count_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // Use only the first 4 addresses from the known keys
    let known_addresses = SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner();
    let initial_addresses = &known_addresses[..4];
    let member_to_remove = initial_addresses[3].0 .0;

    // threshold=2 is valid for 4 members (2 >= MIN_THRESHOLD=2, 2 <= 4-2=2)
    let blob = create_remove_member_tx(member_to_remove, 2, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        initial_addresses,
        2, // threshold=2, valid for 4 members
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            initial_addresses,
            2,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 4); // Still 4, remove was rejected (would go below min=4)
}

#[test]
fn test_add_member_threshold_too_high_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_member = [99u8; 20];
    // After adding, 6 members. Max threshold = 6-2=4. Requesting threshold=5 is invalid.
    let blob = create_add_member_tx(new_member, 5, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 5); // Still 5, add was rejected

    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD); // Threshold unchanged
}

#[test]
fn test_update_threshold_below_min_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // threshold=1 is below MIN_THRESHOLD=2
    let blob = create_update_threshold_tx(1, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD); // Threshold unchanged (still 3)
}

#[test]
fn test_update_threshold_exceeds_proximity_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    // 5 members, max threshold = 5-2=3. Requesting threshold=4 is invalid.
    let blob = create_update_threshold_tx(4, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD); // Threshold unchanged (still 3)
}

#[test]
fn test_update_sequencer_da_pub_key() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_pub_key = [77u8; 33];
    let blob = create_update_sequencer_pub_key_tx(new_pub_key, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let stored_pub_key = SequencerDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_pub_key, new_pub_key.to_vec());
}

#[test]
fn test_update_batch_prover_da_pub_key() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_pub_key = [88u8; 33];
    let blob = create_update_batch_prover_pub_key_tx(new_pub_key, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let stored_pub_key =
        BatchProverDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_pub_key, new_pub_key.to_vec());
}

#[test]
fn test_update_sequencer_da_pub_key_wrong_chain_id_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_pub_key = [77u8; 33];
    // Sign with wrong chain_id in domain (9999 instead of Nightly's 5655)
    let blob =
        create_update_sequencer_pub_key_tx_with_signing_chain_id(new_pub_key, 9999, [11u8; 32], 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // Key should remain unchanged (the initial value)
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let stored_pub_key = SequencerDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_pub_key, sequencer_da_pub_key.to_vec());
}

#[test]
fn test_update_batch_prover_da_pub_key_wrong_chain_id_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    let block_header_1 = MockBlockHeader::from_height(1);

    let new_pub_key = [88u8; 33];
    // Sign with wrong chain_id in domain (9999 instead of Nightly's 5655)
    let blob = create_update_batch_prover_pub_key_tx_with_signing_chain_id(
        new_pub_key,
        9999,
        [11u8; 32],
        1,
    );

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // Key should remain unchanged (the initial value)
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let stored_pub_key =
        BatchProverDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_pub_key, batch_prover_da_pub_key.to_vec());
}

#[test]
fn test_lcp_method_id_upgrade_reinitializes_state() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let old_method_id = [1u32; 8];
    let new_method_id = [2u32; 8];
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

    let l2_genesis_state_root = [1u8; 32];
    let sequencer_da_pub_key = [45; 32];

    // First proof with old method ID — initializes state
    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: old_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![seq_comm_1_blob, blob_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    assert_eq!(output_1.light_client_proof_method_id, old_method_id);
    assert_eq!(output_1.l2_state_root, [2; 32]);
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.last_sequencer_commitment_index, 1);

    // Second proof with new method ID — LCP upgrade with re-initialization
    let block_header_2 = MockBlockHeader::from_height(2);
    let mock_output_1_serialized = create_prev_lcp_serialized(output_1.clone(), true);

    // Use different initial values for the "new circuit" to verify re-initialization
    let new_batch_proof_method_ids: Vec<(u64, [u32; 8])> = vec![(0, [99u32; 8])];
    let new_batch_prover_da_pub_key = [77; 32];
    let new_sequencer_da_pub_key = [88; 32];

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized),
            light_client_proof_method_id: new_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        new_batch_proof_method_ids.clone(),
        &new_batch_prover_da_pub_key,
        &new_sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            new_batch_proof_method_ids.clone(),
            &new_batch_prover_da_pub_key,
            &new_sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[old_method_id], // allowed previous method IDs
        )
        .unwrap();

    // Verify the output has the new method ID
    assert_eq!(output_2.light_client_proof_method_id, new_method_id);

    // Verify L2 state carries over from the previous proof
    assert_eq!(output_2.l2_state_root, output_1.l2_state_root);
    assert_eq!(output_2.last_l2_height, output_1.last_l2_height);
    assert_eq!(
        output_2.last_sequencer_commitment_index,
        output_1.last_sequencer_commitment_index
    );

    // Verify JMT state was re-initialized with new initial constants
    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );

    let stored_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_method_ids, new_batch_proof_method_ids);

    let stored_batch_prover_pub_key =
        BatchProverDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_batch_prover_pub_key, new_batch_prover_da_pub_key);

    let stored_sequencer_pub_key =
        SequencerDaPubKeyAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_sequencer_pub_key, new_sequencer_da_pub_key);

    let stored_threshold =
        SecurityCouncilThresholdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(stored_threshold, INITIAL_SECURITY_COUNCIL_THRESHOLD);
}

#[test]
#[should_panic(expected = "Previous LCP method ID is not in the allowed list")]
fn test_lcp_upgrade_with_disallowed_previous_method_id_panics() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let old_method_id = [1u32; 8];
    let new_method_id = [2u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];

    // First proof with old method ID
    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: old_method_id,
            da_block_header: block_header_1.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // Second proof with new method ID, but allowed list does NOT contain old_method_id
    let block_header_2 = MockBlockHeader::from_height(2);
    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(mock_output_1_serialized.clone()),
            light_client_proof_method_id: new_method_id,
            da_block_header: block_header_2.clone(),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    // This should panic because [3u32; 8] does not contain old_method_id [1u32; 8]
    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input_2,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[[3u32; 8]], // does NOT contain old_method_id [1u32; 8]
        )
        .unwrap();
}

#[test]
fn test_nonce_replay_same_nonce_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Send method id update with nonce=1 (accepted)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);

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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 1);

    // Block 2: Replay the same nonce=1 (should be rejected)
    let block_header_2 = MockBlockHeader::from_height(2);
    let blob_replay = create_new_method_id_tx(20, [3u32; 8], method_id_sender, Network::Nightly, 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_replay],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Still only 2 method ids - the replay was rejected
    assert_eq!(batch_proof_method_ids.len(), 2);
    assert_eq!(
        batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 1); // Nonce unchanged
}

#[test]
fn test_nonce_lower_nonce_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Send method id update with nonce=1 (accepted)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);

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
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // Block 2: Send with nonce=0 (lower than current=1, should be rejected)
    let block_header_2 = MockBlockHeader::from_height(2);
    let blob_lower = create_new_method_id_tx(20, [3u32; 8], method_id_sender, Network::Nightly, 0);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_lower],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 1); // Nonce unchanged
}

#[test]
fn test_nonce_skipped_nonce_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Send with nonce=3 (skipped, expected=1, should be rejected)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_skipped =
        create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 3);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_skipped],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Method id not added because nonce was skipped
    assert_eq!(batch_proof_method_ids.len(), 1);
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 0); // Nonce unchanged from initial
}

#[test]
fn test_nonce_sequential_accepted_then_replay_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Two SC messages with nonce=1 and nonce=2 (both accepted)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_1 = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);
    let blob_2 = create_new_method_id_tx(20, [3u32; 8], method_id_sender, Network::Nightly, 2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_1, blob_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(batch_proof_method_ids.len(), 3);
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 2);

    // Block 2: Try to replay nonce=2 and also send nonce=1 (both rejected), then nonce=3 (accepted)
    let block_header_2 = MockBlockHeader::from_height(2);
    let blob_replay_2 =
        create_new_method_id_tx(30, [4u32; 8], method_id_sender, Network::Nightly, 2);
    let blob_replay_1 =
        create_new_method_id_tx(40, [5u32; 8], method_id_sender, Network::Nightly, 1);
    let blob_valid_3 =
        create_new_method_id_tx(50, [6u32; 8], method_id_sender, Network::Nightly, 3);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_replay_2, blob_replay_1, blob_valid_3],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Only nonce=3 was accepted, so 4 total method ids (initial + 3 valid ones)
    assert_eq!(batch_proof_method_ids.len(), 4);
    assert_eq!(
        batch_proof_method_ids,
        vec![
            (0u64, [0u32; 8]),
            (10u64, [2u32; 8]),
            (20u64, [3u32; 8]),
            (50u64, [6u32; 8]),
        ]
    );
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 3);
}

#[test]
fn test_nonce_cross_message_types() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: method id update with nonce=1, then add member with nonce=2
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_method_id =
        create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);
    let new_member = [99u8; 20];
    let blob_add_member = create_add_member_tx(new_member, 3, method_id_sender, 2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_method_id, blob_add_member],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    // Both messages accepted
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(batch_proof_method_ids.len(), 2);
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(addresses.len(), 6); // 5 initial + 1 new
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 2);

    // Block 2: Try add member with nonce=2 again (replay across different message type, should be rejected)
    let block_header_2 = MockBlockHeader::from_height(2);
    let another_member = [88u8; 20];
    let blob_replay = create_add_member_tx(another_member, 3, method_id_sender, 2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_replay],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let addresses = SecurityCouncilAddressAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Still 6, the replay was rejected
    assert_eq!(addresses.len(), 6);
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 2); // Nonce unchanged
}

#[test]
fn test_remove_batch_proof_method_id() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Add a second method id (nonce=1)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_add = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_add],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
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

    // Block 2: Remove the first method id (index=0, method_id=[0;8], height=0, nonce=2)
    let block_header_2 = MockBlockHeader::from_height(2);
    let blob_remove = create_remove_method_id_tx(0, [0u32; 8], 0, method_id_sender, 2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_remove],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(batch_proof_method_ids.len(), 1);
    assert_eq!(batch_proof_method_ids, vec![(10u64, [2u32; 8])]);
}

#[test]
fn test_remove_last_method_id_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Try to remove the only method id (should be rejected)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_remove = create_remove_method_id_tx(0, [0u32; 8], 0, method_id_sender, 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_remove],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Still 1 — cannot remove the last method id
    assert_eq!(batch_proof_method_ids.len(), 1);
    assert_eq!(batch_proof_method_ids, vec![(0u64, [0u32; 8])]);
}

#[test]
fn test_remove_method_id_wrong_fields_rejected() {
    let db_dir = tempdir().unwrap();
    let native_circuit_runner = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk_circuit_runner = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();

    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9; 32];
    let sequencer_da_pub_key = [45; 32];
    let method_id_sender = [11u8; 32];

    // Block 1: Add a second method id (nonce=1)
    let block_header_1 = MockBlockHeader::from_height(1);
    let blob_add = create_new_method_id_tx(10, [2u32; 8], method_id_sender, Network::Nightly, 1);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id,
            da_block_header: block_header_1,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_add],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
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
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    // Block 2: Three rejected remove attempts:
    // 1. Wrong method_id at index 0 (nonce=2)
    // 2. Wrong activation height at index 1 (nonce=2, prev rejected)
    // 3. Out-of-bounds index (nonce=2, prev rejected)
    let block_header_2 = MockBlockHeader::from_height(2);
    // Wrong method id: index 0 has [0;8] but we claim [9;8]
    let blob_wrong_id = create_remove_method_id_tx(0, [9u32; 8], 0, method_id_sender, 2);
    // Wrong height: index 1 has height=10 but we claim height=99
    let blob_wrong_height = create_remove_method_id_tx(1, [2u32; 8], 99, method_id_sender, 2);
    // Out of bounds: index 5 doesn't exist
    let blob_oob = create_remove_method_id_tx(5, [0u32; 8], 0, method_id_sender, 2);

    let input = native_circuit_runner.run(
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id,
            da_block_header: block_header_2,
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_wrong_id, blob_wrong_height, blob_oob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );

    let _output_2 = zk_circuit_runner
        .run_circuit(
            da_verifier.clone(),
            input,
            ZkStorage::new(),
            Network::Nightly,
            l2_genesis_state_root,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &batch_prover_da_pub_key,
            &sequencer_da_pub_key,
            SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            &[],
        )
        .unwrap();

    let mut working_set = WorkingSet::new(
        native_circuit_runner
            .prover_storage_manager
            .create_final_view_storage(),
    );
    let batch_proof_method_ids =
        BatchProofMethodIdAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    // Still 2 — all three removes were rejected
    assert_eq!(batch_proof_method_ids.len(), 2);
    assert_eq!(
        batch_proof_method_ids,
        vec![(0u64, [0u32; 8]), (10u64, [2u32; 8])]
    );
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut working_set).unwrap();
    assert_eq!(nonce, 2); // Add from block 1 consumed nonce 1, first failed remove consumed nonce 2
}

// ── SetLcpToPreviousState tests ────────────────────────────────────────────────

// Helper: run the circuit through the native runner and then through the ZK
// runner, asserting it succeeds, and return the output.
fn run_block(
    native: &NativeCircuitRunner,
    zk: &LightClientProofCircuit<ZkStorage, MockDaSpec, MockZkGuest>,
    da_verifier: &MockDaVerifier,
    input: LightClientCircuitInput<MockDaSpec>,
    l2_genesis_state_root: [u8; 32],
    batch_prover_da_pub_key: &[u8; 32],
    sequencer_da_pub_key: &[u8; 32],
) -> LightClientCircuitOutput {
    let input = native.run(
        input,
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        batch_prover_da_pub_key,
        sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        Network::Nightly,
    );
    zk.run_circuit(
        da_verifier.clone(),
        input,
        ZkStorage::new(),
        Network::Nightly,
        l2_genesis_state_root,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        batch_prover_da_pub_key,
        sequencer_da_pub_key,
        SECURITY_COUNCIL_INITIAL_DA_ADDRESSES.inner(),
        INITIAL_SECURITY_COUNCIL_THRESHOLD,
        EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
        &[],
    )
    .unwrap()
}

/// Happy path: SetLcpToPreviousState reverts the LCP state to an earlier
/// commitment index, resets l2_state_root / last_l2_height, and increments
/// the revert epoch in persistent storage.
#[test]
fn test_set_lcp_to_previous_state() {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9u8; 32];
    let sequencer_da_pub_key = [45u8; 32];

    // seq_comm_1: index=1, l2_end=2, merkle_root=[2;32]
    // seq_comm_2: index=2, l2_end=3, merkle_root=[3;32]
    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    // batch_proof_1: initial_state=[1;32] → final=[2;32]  (merkle_root of seq_comm_1)
    // batch_proof_2: initial_state=[2;32] → final=[3;32]  (merkle_root of seq_comm_2)
    let blob_seq_1 = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_seq_2 = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let blob_proof_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_proof_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    // Block 1: process both commitments and both batch proofs
    let output_1 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(1),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_seq_1, blob_seq_2, blob_proof_1, blob_proof_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    assert_eq!(output_1.last_sequencer_commitment_index, 2);
    assert_eq!(output_1.l2_state_root, [3u8; 32]);
    assert_eq!(output_1.last_l2_height, 3);

    // Block 2: SetLcpToPreviousState — revert to index=1
    // pre_state_root must match VerifiedStateTransition(1).final_state_root = [2;32]
    // last_l2_height must match seq_comm_1.l2_end_block_number = 2
    // merkle_root must match seq_comm_1.merkle_root = [2;32]
    let revert_blob = create_set_lcp_to_previous_state_tx(
        [2u8; 32], // pre_state_root
        1,         // revert to index 1
        2,         // last_l2_height
        [2u8; 32], // merkle_root
        [11u8; 32], 1, // nonce
    );

    let output_2 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(2),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![revert_blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    // LCP state should be rolled back to index 1
    assert_eq!(output_2.last_sequencer_commitment_index, 1);
    assert_eq!(output_2.l2_state_root, [2u8; 32]);
    assert_eq!(output_2.last_l2_height, 2);

    // Revert epoch must have been incremented to 1
    let mut ws = WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    let epoch = RevertEpochAccessor::<ProverStorage>::get_or_default(&mut ws);
    assert_eq!(epoch, 1);

    // Nonce was consumed
    let nonce = SecurityCouncilNonceAccessor::<ProverStorage>::get(&mut ws).unwrap();
    assert_eq!(nonce, 1);
}

/// After a revert, verified state transitions from the previous epoch must be
/// ignored by the chaining loop so the LCP cannot advance past the revert point
/// using stale data.
#[test]
fn test_set_lcp_to_previous_state_invalidates_stale_proofs() {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9u8; 32];
    let sequencer_da_pub_key = [45u8; 32];

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);

    let blob_seq_1 = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_seq_2 = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let blob_proof_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_proof_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    // Block 1: process seq_comm_1 and seq_comm_2 with their batch proofs
    let output_1 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(1),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_seq_1, blob_seq_2, blob_proof_1, blob_proof_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );
    assert_eq!(output_1.last_sequencer_commitment_index, 2);

    // Block 2: revert to index=1; VerifiedStateTransition(2) is now from epoch 0
    let revert_blob =
        create_set_lcp_to_previous_state_tx([2u8; 32], 1, 2, [2u8; 32], [11u8; 32], 1);
    let output_2 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(2),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![revert_blob],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );
    assert_eq!(output_2.last_sequencer_commitment_index, 1);

    // Block 3: empty DA — chaining loop finds VerifiedStateTransition(2) stored in JMT
    // but its epoch (0) != current_epoch (1), so it must be skipped
    let output_3 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_2, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(3),
            inclusion_proof: [3u8; 32],
            completeness_proof: vec![],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    // Must still be at index 1 — stale transition for index 2 must NOT have advanced it
    assert_eq!(output_3.last_sequencer_commitment_index, 1);
    assert_eq!(output_3.l2_state_root, [2u8; 32]);
}

/// A revert message whose index is equal to (not less than) last_sequencer_commitment_index
/// must be rejected; the LCP state must remain unchanged.
#[test]
fn test_set_lcp_to_previous_state_rejected_if_index_not_less_than_current() {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9u8; 32];
    let sequencer_da_pub_key = [45u8; 32];

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let blob_seq_1 = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_proof_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );

    let output_1 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(1),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_seq_1, blob_proof_1],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );
    assert_eq!(output_1.last_sequencer_commitment_index, 1);

    // Try to revert to index=1 while last_index=1 (index >= last_index → rejected)
    let bad_revert = create_set_lcp_to_previous_state_tx(
        [2u8; 32], 1, // index == last_index, not strictly less
        2, [2u8; 32], [11u8; 32], 1,
    );

    let output_2 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(2),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![bad_revert],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    // State must be unchanged
    assert_eq!(output_2.last_sequencer_commitment_index, 1);
    assert_eq!(output_2.l2_state_root, [2u8; 32]);

    let mut ws = WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    let epoch = RevertEpochAccessor::<ProverStorage>::get_or_default(&mut ws);
    assert_eq!(epoch, 0); // epoch must NOT have been incremented
}

/// A revert message with a mismatched pre_state_root must be rejected.
#[test]
fn test_set_lcp_to_previous_state_rejected_if_pre_state_root_mismatch() {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9u8; 32];
    let sequencer_da_pub_key = [45u8; 32];

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);
    let blob_seq_1 = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_seq_2 = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let blob_proof_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_proof_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let output_1 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(1),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_seq_1, blob_seq_2, blob_proof_1, blob_proof_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );
    assert_eq!(output_1.last_sequencer_commitment_index, 2);

    // pre_state_root is wrong — does not match VerifiedStateTransition(1).final_state_root
    let bad_revert = create_set_lcp_to_previous_state_tx(
        [0xFFu8; 32], // wrong pre_state_root
        1,
        2,
        [2u8; 32],
        [11u8; 32],
        1,
    );

    let output_2 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(2),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![bad_revert],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    // State must be unchanged
    assert_eq!(output_2.last_sequencer_commitment_index, 2);
    assert_eq!(output_2.l2_state_root, [3u8; 32]);

    let mut ws = WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    let epoch = RevertEpochAccessor::<ProverStorage>::get_or_default(&mut ws);
    assert_eq!(epoch, 0);
}

/// A revert message that references an index with no verified state transition
/// stored must be rejected.
#[test]
fn test_set_lcp_to_previous_state_rejected_if_no_verified_transition() {
    let db_dir = tempdir().unwrap();
    let native = NativeCircuitRunner::new(db_dir.path().to_path_buf());
    let zk = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new();
    let da_verifier = MockDaVerifier {};

    let l2_genesis_state_root = [1u8; 32];
    let batch_prover_da_pub_key = [9u8; 32];
    let sequencer_da_pub_key = [45u8; 32];

    let seq_comm_1 = create_mock_sequencer_commitment(1, 2, [2u8; 32]);
    let seq_comm_2 = create_mock_sequencer_commitment(2, 3, [3u8; 32]);
    let blob_seq_1 = create_mock_sequencer_commitment_blob(seq_comm_1.clone());
    let blob_seq_2 = create_mock_sequencer_commitment_blob(seq_comm_2.clone());
    let blob_proof_1 = create_mock_batch_proof(
        [1u8; 32],
        2,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_1.clone()],
        None,
        batch_prover_da_pub_key,
    );
    let blob_proof_2 = create_mock_batch_proof(
        [2u8; 32],
        3,
        true,
        MockBlockHeader::from_height(1).hash.0,
        vec![seq_comm_2.clone()],
        Some(seq_comm_1.serialize_and_calculate_sha_256()),
        batch_prover_da_pub_key,
    );

    let output_1 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: None,
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(1),
            inclusion_proof: [1u8; 32],
            completeness_proof: vec![blob_seq_1, blob_seq_2, blob_proof_1, blob_proof_2],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );
    assert_eq!(output_1.last_sequencer_commitment_index, 2);

    // Try to revert to index=0; there is no VerifiedStateTransition at index 0
    // (the circuit never stores one there — index starts at 1)
    let bad_revert = create_set_lcp_to_previous_state_tx(
        [1u8; 32], // genesis root — irrelevant, check happens after index check
        0,         // index=0, no verified transition stored here
        0, [0u8; 32], [11u8; 32], 1,
    );

    let output_2 = run_block(
        &native,
        &zk,
        &da_verifier,
        LightClientCircuitInput {
            previous_light_client_proof: Some(create_prev_lcp_serialized(output_1, true)),
            light_client_proof_method_id: [1u32; 8],
            da_block_header: MockBlockHeader::from_height(2),
            inclusion_proof: [2u8; 32],
            completeness_proof: vec![bad_revert],
            witness: Default::default(),
        },
        l2_genesis_state_root,
        &batch_prover_da_pub_key,
        &sequencer_da_pub_key,
    );

    assert_eq!(output_2.last_sequencer_commitment_index, 2);
    assert_eq!(output_2.l2_state_root, [3u8; 32]);

    let mut ws = WorkingSet::new(native.prover_storage_manager.create_final_view_storage());
    let epoch = RevertEpochAccessor::<ProverStorage>::get_or_default(&mut ws);
    assert_eq!(epoch, 0);
}
