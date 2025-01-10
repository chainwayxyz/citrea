use std::collections::{BTreeMap, VecDeque};

use rand::{thread_rng, Rng};
use sov_mock_da::{MockAddress, MockBlob, MockDaSpec, MockHash};
use sov_mock_zkvm::{MockCodeCommitment, MockJournal, MockProof};
use sov_rollup_interface::da::{BatchProofMethodId, BlobReaderTrait, DaDataLightClient};
use sov_rollup_interface::mmr::{InMemoryStore, MMRChunk, MMRGuest, MMRInclusionProof, MMRNative};
use sov_rollup_interface::zk::{BatchProofCircuitOutput, LightClientCircuitOutput};

pub(crate) fn create_mock_batch_proof(
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

    let mut blob = MockBlob::new(da_data_ser, MockAddress::new([9u8; 32]), [0u8; 32], None);
    blob.full_data();

    blob
}

pub(crate) fn create_serialized_mock_proof(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    is_valid: bool,
    state_diff: Option<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
) -> Vec<u8> {
    let batch_proof_method_id = MockCodeCommitment([2u8; 32]);

    let bp = BatchProofCircuitOutput::<MockDaSpec, [u8; 32]> {
        initial_state_root,
        final_state_root,
        prev_soft_confirmation_hash: [3; 32],
        final_soft_confirmation_hash: [4; 32],
        state_diff: state_diff.unwrap_or_default(),
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

    mock_proof.encode_to_vec()
}

pub(crate) fn create_prev_lcp_serialized(
    output: LightClientCircuitOutput,
    is_valid: bool,
) -> Vec<u8> {
    let serialized = borsh::to_vec(&output).expect("should serialize");
    match is_valid {
        true => borsh::to_vec(&MockJournal::Verifiable(serialized)).unwrap(),
        false => borsh::to_vec(&MockJournal::Unverifiable(serialized)).unwrap(),
    }
}

pub(crate) fn create_new_method_id_tx(
    activation_height: u64,
    new_method_id: [u32; 8],
    pub_key: [u8; 32],
) -> MockBlob {
    let da_data = DaDataLightClient::BatchProofMethodId(BatchProofMethodId {
        method_id: new_method_id,
        activation_l2_height: activation_height,
    });

    let da_data_ser = borsh::to_vec(&da_data).expect("should serialize");

    let mut blob = MockBlob::new(da_data_ser, MockAddress::new(pub_key), [0u8; 32], None);
    blob.full_data();

    blob
}

pub(crate) fn create_random_state_diff(size_in_kb: u64) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    let mut rng = thread_rng();
    let mut map = BTreeMap::new();
    let mut total_size: u64 = 0;

    // Convert size to bytes
    let size_in_bytes = size_in_kb * 1024;

    while total_size < size_in_bytes {
        // Generate a random 32-byte key
        let key: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        // Randomly decide if the value is `None` or a `Vec<u8>` of random length
        let value: Option<Vec<u8>> = if rng.gen_bool(0.1) {
            None
        } else {
            let value_size: usize = rng.gen_range(1..=2048);
            Some((0..value_size).map(|_| rng.gen::<u8>()).collect())
        };

        // Calculate the size of the key and value
        let key_size = key.len() as u64;
        let value_size = match &value {
            Some(v) => v.len() as u64 + 1,
            None => 1,
        };

        // Add to the map
        map.insert(key, value);

        // Update the total size
        total_size += key_size + value_size;
    }

    map
}

pub(crate) fn create_mmr_hints(
    mmr_guest: &mut MMRGuest,
    chunks: Vec<([u8; 32], Vec<u8>)>,
) -> VecDeque<(MMRChunk, MMRInclusionProof)> {
    let mut mmr = MMRNative::new(InMemoryStore::default());
    for chunk in chunks.iter() {
        mmr.append(MMRChunk::new(chunk.0, chunk.1.clone())).unwrap();
    }

    let mut mmr_hints = VecDeque::new();
    for chunk in chunks.iter() {
        let (chunk, proof) = mmr.generate_proof(chunk.0).unwrap().unwrap();
        mmr_guest.append(chunk.clone());
        mmr_hints.push_back((chunk, proof));
    }

    mmr_hints
}
