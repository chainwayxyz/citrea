use std::collections::BTreeMap;

use sov_mock_da::{MockAddress, MockBlob, MockDaSpec, MockHash};
use sov_mock_zkvm::{MockCodeCommitment, MockJournal, MockProof};
use sov_rollup_interface::da::{BlobReaderTrait, DaDataLightClient};
use sov_rollup_interface::zk::{BatchProofCircuitOutput, LightClientCircuitOutput};

pub(crate) fn create_mock_blob(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    is_valid: bool,
) -> MockBlob {
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);

    let bp = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root,
        final_state_root,
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: BTreeMap::new(),
        da_slot_hash: MockHash([5; 32]),
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: [9; 32].to_vec(),
        sequencer_da_public_key: [9; 32].to_vec(),
        last_l2_height,
        preproven_commitments: vec![],
    };

    let bp_serialized = borsh::to_vec(&bp).expect("should serialize");

    let serialized_journal = match is_valid {
        true => borsh::to_vec(&MockJournal::Verifiable(bp_serialized.clone())).unwrap(),
        false => borsh::to_vec(&MockJournal::Unverifiable(bp_serialized.clone())).unwrap(),
    };

    let mock_proof = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid: true,
        log: serialized_journal.clone(),
    };

    let mock_serialized = mock_proof.encode_to_vec();

    let da_data = DaDataLightClient::Complete(mock_serialized);
    let da_data_ser = borsh::to_vec(&da_data).expect("should serialize");

    let mut blob = MockBlob::new(da_data_ser, MockAddress::new([9u8; 32]), [0u8; 32]);
    blob.full_data();

    blob
}

pub(crate) fn create_prev_lcp_serialized(
    output: LightClientCircuitOutput<MockDaSpec>,
    is_valid: bool,
) -> Vec<u8> {
    let serialized = borsh::to_vec(&output).expect("should serialize");
    match is_valid {
        true => borsh::to_vec(&MockJournal::Verifiable(serialized)).unwrap(),
        false => borsh::to_vec(&MockJournal::Unverifiable(serialized)).unwrap(),
    }
}
