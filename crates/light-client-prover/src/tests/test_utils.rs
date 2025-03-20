use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use rand::{thread_rng, Rng};
use sov_mock_da::{MockAddress, MockBlob, MockDaSpec, MockDaVerifier};
use sov_mock_zkvm::{MockCodeCommitment, MockJournal, MockProof, MockZkvm};
use sov_modules_api::Zkvm;
use sov_prover_storage_manager::{Config, ProverStorage, ProverStorageManager};
use sov_rollup_interface::da::{BatchProofMethodId, BlobReaderTrait, DaVerifier, DataOnDa};
use sov_rollup_interface::zk::batch_proof::output::v3::BatchProofCircuitOutputV3;
use sov_rollup_interface::zk::batch_proof::output::{BatchProofCircuitOutput, CumulativeStateDiff};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;

use crate::circuit::LightClientProofCircuit;

pub(crate) fn create_mock_batch_proof(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    is_valid: bool,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
) -> MockBlob {
    let batch_proof_method_id = MockCodeCommitment([0u8; 32]);

    //TODO: FIXME The new added values are all wrong
    let bp = BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
        initial_state_root,
        final_state_root,
        final_l2_block_hash: [4; 32],
        state_diff: BTreeMap::new(),
        last_l2_height,
        // TODO: Update this
        sequencer_commitment_hashes: vec![],
        last_l1_hash_on_bitcoin_light_client_contract,
        sequencer_commitment_index_range: (0, 0),
        previous_commitment_index: None,
        previous_commitment_hash: None,
    });

    let bp_serialized = borsh::to_vec(&bp).expect("should serialize");

    let serialized_journal =
        borsh::to_vec(&MockJournal::Verifiable(bp_serialized.clone())).unwrap();

    let mock_proof = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid,
        log: serialized_journal.clone(),
    };

    let mock_serialized = mock_proof.encode_to_vec();

    let da_data = DataOnDa::Complete(mock_serialized);
    let da_data_ser = borsh::to_vec(&da_data).expect("should serialize");

    let blob = MockBlob::new(da_data_ser, MockAddress::new([9u8; 32]), [0u8; 32], None);
    blob.full_data();

    blob
}

pub(crate) fn create_serialized_mock_proof(
    initial_state_root: [u8; 32],
    final_state_root: [u8; 32],
    last_l2_height: u64,
    is_valid: bool,
    state_diff: Option<CumulativeStateDiff>,
    last_l1_hash_on_bitcoin_light_client_contract: [u8; 32],
) -> Vec<u8> {
    let batch_proof_method_id = MockCodeCommitment([0u8; 32]);

    //TODO: FIXME The new added values are all wrong
    let bp = BatchProofCircuitOutput::V3(BatchProofCircuitOutputV3 {
        initial_state_root,
        final_state_root,
        final_l2_block_hash: [4; 32],
        state_diff: state_diff.unwrap_or_default(),
        last_l2_height,
        // TODO: Update this
        sequencer_commitment_hashes: vec![],
        last_l1_hash_on_bitcoin_light_client_contract,
        sequencer_commitment_index_range: (0, 0),
        previous_commitment_index: None,
        previous_commitment_hash: None,
    });

    let bp_serialized = borsh::to_vec(&bp).expect("should serialize");

    let serialized_journal =
        borsh::to_vec(&MockJournal::Verifiable(bp_serialized.clone())).unwrap();

    let mock_proof = MockProof {
        program_id: batch_proof_method_id.clone(),
        is_valid,
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
    let da_data = DataOnDa::BatchProofMethodId(BatchProofMethodId {
        method_id: new_method_id,
        activation_l2_height: activation_height,
    });

    let da_data_ser = borsh::to_vec(&da_data).expect("should serialize");

    let blob = MockBlob::new(da_data_ser, MockAddress::new(pub_key), [0u8; 32], None);
    blob.full_data();

    blob
}

pub(crate) fn create_random_state_diff(size_in_kb: u64) -> BTreeMap<Arc<[u8]>, Option<Arc<[u8]>>> {
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
        map.insert(
            Arc::from(key.into_boxed_slice()),
            value.map(|v| Arc::from(v.into_boxed_slice())),
        );

        // Update the total size
        total_size += key_size + value_size;
    }

    map
}

/// MockDA MockZkvm native context circuit runner implementation
pub struct NativeCircuitRunner {
    circuit: LightClientProofCircuit<ProverStorage, MockDaSpec, MockZkvm>,
    pub(crate) prover_storage_manager: ProverStorageManager,
}

impl NativeCircuitRunner {
    pub fn new(db_path: PathBuf) -> Self {
        let prover_storage_manager = ProverStorageManager::new(Config {
            path: db_path,
            db_max_open_files: None,
        })
        .unwrap();
        let circuit = LightClientProofCircuit::new();

        Self {
            circuit,
            prover_storage_manager,
        }
    }

    /// Run the circuit with the given input and return the input with its witness filled
    /// that will be used to run the circuit in ZK context
    pub fn run(
        &self,
        mut input: LightClientCircuitInput<MockDaSpec>,
        l2_genesis_state_root: [u8; 32],
        inital_batch_proof_method_ids: Vec<(u64, [u32; 8])>,
        batch_prover_da_pub_key: &[u8],
        method_id_upgrade_authority: &[u8],
    ) -> LightClientCircuitInput<MockDaSpec> {
        let prover_storage = self
            .prover_storage_manager
            .create_storage_for_next_l2_height();

        let prev_lcp_output = input
            .previous_light_client_proof_journal
            .clone()
            .map(|j| MockZkvm::deserialize_output(&j).unwrap());

        let da_verifier = MockDaVerifier {};

        // Hack for mock da and mockzkvm usage
        let da_txs = da_verifier
            .verify_transactions(
                &input.da_block_header,
                input.inclusion_proof,
                input.completeness_proof.clone(),
            )
            .unwrap();

        let res = self.circuit.run_l1_block(
            prover_storage,
            Default::default(),
            da_txs,
            input.da_block_header.clone(),
            prev_lcp_output,
            l2_genesis_state_root,
            inital_batch_proof_method_ids,
            batch_prover_da_pub_key,
            method_id_upgrade_authority,
        );

        self.prover_storage_manager.finalize_storage(res.change_set);

        input.witness = res.witness;

        input
    }
}
