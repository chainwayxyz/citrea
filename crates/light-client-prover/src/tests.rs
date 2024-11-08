use std::thread;

use citrea_common::da;
use sov_mock_da::{MockAddress, MockDaService, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::{MockCodeCommitment, MockProof, MockZkGuest};
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaData, DaDataBatchProof, DaDataLightClient, DaNamespace,
    DaSpec, SequencerCommitment, Time,
};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{
    BatchProofCircuitOutput, LightClientCircuitInput, LightClientCircuitOutput, Zkvm, ZkvmGuest,
};
use tempfile;

use crate::circuit::run_circuit;

#[test]
fn test_light_client_circuit() {
    let light_client_proof_method_id = MockCodeCommitment([1; 32]);
    let batch_proof_method_id = MockCodeCommitment([2; 32]);
    let da_verifier = MockDaVerifier::new();
    let da_service = MockDaService::new(MockAddress::from([9; 32]), tempfile::tempdir().unwrap());

    let da_data_0 = DaData::ZKProof(MockProof([3; 32]));
    let da_data_1 = DaData::ZKProof(MockProof([4; 32]));
    da_service.send_transaction(da_data);

    let bp_output = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root: [1; 32],
        final_state_root: [2; 32],
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: vec![],
        da_slot_hash: [5; 32],
        sequencer_commitments_range: (0, 0),
        sequencer_public_key: MockAddress::from([9; 32]),
        sequencer_da_public_key: MockAddress::from([9; 32]),
        validity_condition: (),
        last_l2_height: 1,
        preproven_commitments: vec![],
    };

    // TODO: use this with mock proof, put this in logs as vecu8 then when extract raw output is called get the logs,
    // after that this will be given to verify and extrac which should just borsh deserialize and give you the output above

    // let previous_light_client_proof_journal = LightClientCircuitOutput::<MockDaSpec> {
    //     state_root: [1; 32],
    //     light_client_proof_method_id,
    //     da_block_hash: [2; 32],
    //     da_block_height: 3,
    //     da_total_work: [4; 32],
    //     da_current_target_bits: 5,
    //     da_epoch_start_time: 0,
    //     da_prev_11_timestamps: [6; 11],
    //     unchained_batch_proofs_info: vec![],
    //     last_l2_height: 1,
    //     l2_genesis_state_root: [15u8; 32],
    // };

    let input = LightClientCircuitInput::<MockDaSpec> {
        previous_light_client_proof_journal: None,
        light_client_proof_method_id,
        da_block_header: Default::default(),
        da_data: vec![da_data_0, da_data_1],
        inclusion_proof: vec![],
        completeness_proof: vec![],
        l2_genesis_state_root: Some([15u8; 32]),
        batch_proof_method_id,
        batch_prover_da_pub_key: MockAddress::from([9; 32]),
    };

    let serialized_input = borsh::to_vec(&input).expect("should serialize");

    let guest = MockZkGuest::new(serialized_input);

    let _ = run_circuit(da_verifier, &guest);
}
