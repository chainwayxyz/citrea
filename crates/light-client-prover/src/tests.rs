use std::collections::BTreeMap;

use sov_mock_da::{
    MockAddress, MockBlob, MockBlockHeader, MockDaSpec, MockDaVerifier, MockHash, MockValidityCond,
};
use sov_mock_zkvm::{MockCodeCommitment, MockProof, MockZkGuest};
use sov_rollup_interface::da::{BlobReaderTrait, DaDataLightClient};
use sov_rollup_interface::zk::{BatchProofCircuitOutput, LightClientCircuitInput};

use crate::circuit::{run_circuit, LightClientVerificationError};

#[test]
fn test_light_client_circuit_valid_da_valid_data() {
    let light_client_proof_method_id = [1u32; 8];
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);
    let da_verifier = MockDaVerifier {};

    let bp_1_2 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [1; 32],
        final_state_root: [2; 32],
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: BTreeMap::new(),
        da_slot_hash: MockHash([5; 32]),
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: [9; 32].to_vec(),
        sequencer_da_public_key: [9; 32].to_vec(),
        validity_condition: MockValidityCond { is_valid: true },
        last_l2_height: 2,
        preproven_commitments: vec![],
    };

    let bp_1_2_serialized = borsh::to_vec(&bp_1_2).expect("should serialize");

    let mock_proof_1_2 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_1_2_serialized.clone(),
    };

    let mock_1_2_serialized = mock_proof_1_2.encode_to_vec();

    let bp_2_3 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [2; 32],
        final_state_root: [3; 32],
        last_l2_height: 3,
        ..bp_1_2
    };
    let bp_2_3_serialized = borsh::to_vec(&bp_2_3).expect("should serialize");

    let mock_proof_2_3 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_2_3_serialized.clone(),
    };

    let mock_2_3_serialized = mock_proof_2_3.encode_to_vec();

    let da_data_1 = DaDataLightClient::Complete(mock_1_2_serialized);
    let da_data_1_ser = borsh::to_vec(&da_data_1).expect("should serialize");
    let da_data_2 = DaDataLightClient::Complete(mock_2_3_serialized);
    let da_data_2_ser = borsh::to_vec(&da_data_2).expect("should serialize");

    let mut blob_1 = MockBlob::new(da_data_1_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_1.full_data();
    let mut blob_2 = MockBlob::new(da_data_2_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_2.full_data();

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

    // Now get more proofs to see the previous light client part is also working correctly
    let bp_3_4 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [3; 32],
        final_state_root: [4; 32],
        last_l2_height: 4,
        ..bp_2_3
    };

    let bp_3_4_serialized = borsh::to_vec(&bp_3_4).expect("should serialize");

    let mock_proof_3_4 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_3_4_serialized.clone(),
    };

    let mock_3_4_serialized = mock_proof_3_4.encode_to_vec();

    let bp_4_5 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [4; 32],
        final_state_root: [5; 32],
        last_l2_height: 5,
        ..bp_3_4
    };

    let bp_4_5_serialized = borsh::to_vec(&bp_4_5).expect("should serialize");

    let mock_proof_4_5 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_4_5_serialized.clone(),
    };

    let mock_4_5_serialized = mock_proof_4_5.encode_to_vec();

    let da_data_3 = DaDataLightClient::Complete(mock_3_4_serialized);
    let da_data_3_ser = borsh::to_vec(&da_data_3).expect("should serialize");
    let da_data_4 = DaDataLightClient::Complete(mock_4_5_serialized);
    let da_data_4_ser = borsh::to_vec(&da_data_4).expect("should serialize");

    let mut blob_3 = MockBlob::new(da_data_3_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_3.full_data();
    let mut blob_4 = MockBlob::new(da_data_4_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_4.full_data();

    let block_header_2 = MockBlockHeader::from_height(2);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(borsh::to_vec(&output_1).unwrap()),
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

    let output_2 = run_circuit(da_verifier, &guest).unwrap();

    // Check that the state transition actually happened
    assert_eq!(output_2.state_root, [5; 32]);
    assert!(output_2.unchained_batch_proofs_info.is_empty());
    assert_eq!(output_2.last_l2_height, 5);
}

#[test]
fn test_wrong_order_da_blocks_should_still_work() {
    let light_client_proof_method_id = [1u32; 8];
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);
    let da_verifier = MockDaVerifier {};

    let bp_1_2 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [1; 32],
        final_state_root: [2; 32],
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: BTreeMap::new(),
        da_slot_hash: MockHash([5; 32]),
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: [9; 32].to_vec(),
        sequencer_da_public_key: [9; 32].to_vec(),
        validity_condition: MockValidityCond { is_valid: true },
        last_l2_height: 2,
        preproven_commitments: vec![],
    };

    let bp_1_2_serialized = borsh::to_vec(&bp_1_2).expect("should serialize");

    let mock_proof_1_2 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_1_2_serialized.clone(),
    };

    let mock_1_2_serialized = mock_proof_1_2.encode_to_vec();

    let bp_2_3 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [2; 32],
        final_state_root: [3; 32],
        last_l2_height: 3,
        ..bp_1_2
    };
    let bp_2_3_serialized = borsh::to_vec(&bp_2_3).expect("should serialize");

    let mock_proof_2_3 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_2_3_serialized.clone(),
    };

    let mock_2_3_serialized = mock_proof_2_3.encode_to_vec();

    let da_data_1 = DaDataLightClient::Complete(mock_1_2_serialized);
    let da_data_1_ser = borsh::to_vec(&da_data_1).expect("should serialize");
    let da_data_2 = DaDataLightClient::Complete(mock_2_3_serialized);
    let da_data_2_ser = borsh::to_vec(&da_data_2).expect("should serialize");

    let mut blob_1 = MockBlob::new(da_data_1_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_1.full_data();
    let mut blob_2 = MockBlob::new(da_data_2_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_2.full_data();

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
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);
    let da_verifier = MockDaVerifier {};

    let bp_2_3 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [2; 32],
        final_state_root: [3; 32],
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: BTreeMap::new(),
        da_slot_hash: MockHash([5; 32]),
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: [9; 32].to_vec(),
        sequencer_da_public_key: [9; 32].to_vec(),
        validity_condition: MockValidityCond { is_valid: true },
        last_l2_height: 3,
        preproven_commitments: vec![],
    };

    let bp_2_3_serialized = borsh::to_vec(&bp_2_3).expect("should serialize");

    let mock_proof_2_3 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_2_3_serialized.clone(),
    };

    let mock_2_3_serialized = mock_proof_2_3.encode_to_vec();

    let bp_3_4 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [3; 32],
        final_state_root: [4; 32],
        last_l2_height: 4,
        ..bp_2_3.clone()
    };
    let bp_3_4_serialized = borsh::to_vec(&bp_3_4).expect("should serialize");

    let mock_proof_3_4 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_3_4_serialized.clone(),
    };

    let mock_3_4_serialized = mock_proof_3_4.encode_to_vec();

    let da_data_1 = DaDataLightClient::Complete(mock_2_3_serialized);
    let da_data_1_ser = borsh::to_vec(&da_data_1).expect("should serialize");
    let da_data_2 = DaDataLightClient::Complete(mock_3_4_serialized);
    let da_data_2_ser = borsh::to_vec(&da_data_2).expect("should serialize");

    let mut blob_1 = MockBlob::new(da_data_1_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_1.full_data();
    let mut blob_2 = MockBlob::new(da_data_2_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_2.full_data();

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

    let bp_1_2 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [1; 32],
        final_state_root: [2; 32],
        last_l2_height: 2,
        ..bp_2_3.clone()
    };
    let bp_1_2_serialized = borsh::to_vec(&bp_1_2).expect("should serialize");

    let mock_proof_1_2 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_1_2_serialized.clone(),
    };

    let mock_1_2_serialized = mock_proof_1_2.encode_to_vec();

    let da_data_1 = DaDataLightClient::Complete(mock_1_2_serialized);
    let da_data_1_ser = borsh::to_vec(&da_data_1).expect("should serialize");

    let mut blob_1 = MockBlob::new(da_data_1_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_1.full_data();

    let block_header_2 = MockBlockHeader::from_height(2);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(borsh::to_vec(&output_1).unwrap()),
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
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);
    let da_verifier = MockDaVerifier {};

    let bp_1_2 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [1; 32],
        final_state_root: [2; 32],
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: BTreeMap::new(),
        da_slot_hash: MockHash([5; 32]),
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: [9; 32].to_vec(),
        sequencer_da_public_key: [9; 32].to_vec(),
        validity_condition: MockValidityCond { is_valid: true },
        last_l2_height: 2,
        preproven_commitments: vec![],
    };

    let bp_1_2_serialized = borsh::to_vec(&bp_1_2).expect("should serialize");

    let mock_proof_1_2 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_1_2_serialized.clone(),
    };

    let mock_1_2_serialized = mock_proof_1_2.encode_to_vec();

    let bp_2_3 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [2; 32],
        final_state_root: [3; 32],
        last_l2_height: 3,
        ..bp_1_2
    };
    let bp_2_3_serialized = borsh::to_vec(&bp_2_3).expect("should serialize");

    let mock_proof_2_3 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_2_3_serialized.clone(),
    };

    let mock_2_3_serialized = mock_proof_2_3.encode_to_vec();

    let da_data_1 = DaDataLightClient::Complete(mock_1_2_serialized);
    let da_data_1_ser = borsh::to_vec(&da_data_1).expect("should serialize");
    let da_data_2 = DaDataLightClient::Complete(mock_2_3_serialized);
    let da_data_2_ser = borsh::to_vec(&da_data_2).expect("should serialize");

    let mut blob_1 = MockBlob::new(da_data_1_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_1.full_data();
    let mut blob_2 = MockBlob::new(da_data_2_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_2.full_data();

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

    let bp_3_4 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [3; 32],
        final_state_root: [4; 32],
        last_l2_height: 4,
        ..bp_2_3
    };

    let bp_3_4_serialized = borsh::to_vec(&bp_3_4).expect("should serialize");

    let mock_proof_3_4 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_3_4_serialized.clone(),
    };

    let mock_3_4_serialized = mock_proof_3_4.encode_to_vec();

    let bp_4_5 = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [4; 32],
        final_state_root: [5; 32],
        last_l2_height: 5,
        ..bp_3_4
    };

    let bp_4_5_serialized = borsh::to_vec(&bp_4_5).expect("should serialize");

    let mock_proof_4_5 = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: bp_4_5_serialized.clone(),
    };

    let mock_4_5_serialized = mock_proof_4_5.encode_to_vec();

    let da_data_3 = DaDataLightClient::Complete(mock_3_4_serialized);
    let da_data_3_ser = borsh::to_vec(&da_data_3).expect("should serialize");
    let da_data_4 = DaDataLightClient::Complete(mock_4_5_serialized);
    let da_data_4_ser = borsh::to_vec(&da_data_4).expect("should serialize");

    let mut blob_3 = MockBlob::new(da_data_3_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_3.full_data();
    let mut blob_4 = MockBlob::new(da_data_4_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob_4.full_data();

    let block_header_2 = MockBlockHeader::from_height(3);

    let input_2 = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: Some(borsh::to_vec(&output_1).unwrap()),
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
