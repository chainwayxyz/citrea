mod test_utils;

use sov_mock_da::{MockBlockHeader, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::MockZkGuest;
use sov_rollup_interface::zk::LightClientCircuitInput;
use test_utils::{create_mock_blob, create_prev_lcp_serialized};

use crate::circuit::{run_circuit, LightClientVerificationError};

#[test]
fn test_light_client_circuit_valid_da_valid_data() {
    let light_client_proof_method_id = [1u32; 8];
    let batch_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);
    let blob_2 = create_mock_blob([2u8; 32], [3u8; 32], 3, true);

    let block_header_1 = MockBlockHeader::from_height(1);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_1, blob_2],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let mut guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);

    // Now get more proofs to see the previous light client part is also working correctly
    let blob_3 = create_mock_blob([3u8; 32], [4u8; 32], 4, true);
    let blob_4 = create_mock_blob([4u8; 32], [5u8; 32], 5, true);

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_serialized = create_prev_lcp_serialized(output_1, true);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(mock_output_1_serialized),
        da_block_header: block_header_2,
        da_data: vec![blob_3, blob_4],
        light_client_proof_method_id,
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: None,
        batch_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input_2 = borsh::to_vec(&input_2).expect("should serialize");

    guest.input = serialized_input_2;

    let output_2 = run_circuit(da_verifier, &guest).unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.state_root, [5; 32]);
    assert!(output_2.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_2.last_l2_height, 5);
}

#[test]
fn test_wrong_order_da_blocks_should_still_work() {
    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);
    let blob_2 = create_mock_blob([2u8; 32], [3u8; 32], 3, true);

    let block_header_1 = MockBlockHeader::from_height(1);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_2, blob_1],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id: light_client_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);
}

#[test]
fn create_unchainable_outputs_then_chain_them_on_next_block() {
    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let block_header_1 = MockBlockHeader::from_height(1);

    let blob_1 = create_mock_blob([2u8; 32], [3u8; 32], 3, true);
    let blob_2 = create_mock_blob([3u8; 32], [4u8; 32], 4, true);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_2, blob_1],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id: light_client_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let mut guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition has not happened because we are missing 1->2
    assert_eq!(output_1.state_root, [1; 32]);
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
    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);

    let block_header_2 = MockBlockHeader::from_height(2);

    let mock_output_1_ser = create_prev_lcp_serialized(output_1, true);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(mock_output_1_ser),
        da_block_header: block_header_2,
        da_data: vec![blob_1],
        l2_genesis_state_root: None,
        ..input
    };

    guest.input = borsh::to_vec(&input_2).unwrap();

    let output_2 = run_circuit(da_verifier, &guest).unwrap();

    // Check that the state transition actually happened from 1-4 now

    assert_eq!(output_2.state_root, [4; 32]);
    assert!(output_2.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_2.last_l2_height, 4);
}

#[test]
fn test_header_chain_proof_height_and_hash() {
    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};

    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);
    let blob_2 = create_mock_blob([2u8; 32], [3u8; 32], 3, true);

    let block_header_1 = MockBlockHeader::from_height(1);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_1, blob_2],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id: light_client_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let mut guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_1.state_root, [3; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 3);

    // Now give l1 block with height 3
    let blob_3 = create_mock_blob([3u8; 32], [4u8; 32], 4, true);
    let blob_4 = create_mock_blob([4u8; 32], [5u8; 32], 5, true);

    let block_header_2 = MockBlockHeader::from_height(3);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, true);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(prev_lcp_out),
        da_block_header: block_header_2,
        da_data: vec![blob_3, blob_4],
        light_client_proof_method_id,
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: None,
        batch_proof_method_id: light_client_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input_2 = borsh::to_vec(&input_2).expect("should serialize");

    guest.input = serialized_input_2;

    // Header chain verification must fail because the l1 block 3 was given before l1 block 2
    let res = run_circuit(da_verifier, &guest);
    assert!(matches!(
        res,
        Err(LightClientVerificationError::HeaderChainVerificationFailed)
    ));
}

#[test]
fn test_unverifiable_batch_proofs() {
    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};
    let batch_proof_method_id = [2u32; 8];

    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);
    let blob_2 = create_mock_blob([2u8; 32], [3u8; 32], 3, false);

    let block_header_1 = MockBlockHeader::from_height(1);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_1, blob_2],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert_eq!(output_1.state_root, [2; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.unchained_batch_proofs_info.len(), 0);
}

#[test]
fn test_unverifiable_prev_light_client_proof() {
    let light_client_proof_method_id = [1u32; 8];
    let da_verifier = MockDaVerifier {};
    let batch_proof_method_id = [2u32; 8];

    let blob_1 = create_mock_blob([1u8; 32], [2u8; 32], 2, true);
    let blob_2 = create_mock_blob([2u8; 32], [3u8; 32], 3, false);

    let block_header_1 = MockBlockHeader::from_height(1);

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: block_header_1,
        da_data: vec![blob_1, blob_2],
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: Some([1u8; 32]),
        batch_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let mut guest = MockZkGuest::new(serialized_input);

    let output_1 = run_circuit(da_verifier.clone(), &guest).unwrap();

    // Check that the state transition actually happened but only for verified batch proof
    // and assert the unverified is ignored, so it is not even in the unchained outputs
    assert_eq!(output_1.state_root, [2; 32]);
    assert!(output_1.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_1.last_l2_height, 2);
    assert_eq!(output_1.unchained_batch_proofs_info.len(), 0);

    let block_header_2 = MockBlockHeader::from_height(2);

    let prev_lcp_out = create_prev_lcp_serialized(output_1, false);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(prev_lcp_out),
        da_block_header: block_header_2,
        da_data: vec![],
        light_client_proof_method_id,
        inclusion_proof: [1u8; 32],
        completeness_proof: (),
        l2_genesis_state_root: None,
        batch_proof_method_id: light_client_proof_method_id,
        batch_prover_da_pub_key: [9; 32].to_vec(),
    };

    guest.input = borsh::to_vec(&input_2).unwrap();

    let res = run_circuit(da_verifier, &guest);
    assert!(matches!(
        res,
        Err(LightClientVerificationError::InvalidPreviousLightClientProof)
    ));
}
