#![no_main]
use citrea_light_client_prover::circuit::initial_values::mockda::{
    BATCH_PROVER_DA_PUBLIC_KEY, GENESIS_ROOT, INITIAL_BATCH_PROOF_METHOD_IDS,
    METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEYS, SEQUENCER_DA_PUBLIC_KEY,
};
use citrea_light_client_prover::circuit::LightClientProofCircuit;
use citrea_primitives::risc0_cutoff::risc0_cutoff;
use citrea_sp1::guest::SP1Guest;
use sov_mock_da::{MockDaSpec, MockDaVerifier};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

sp1_zkvm::entrypoint!(main);

const NETWORK: Network = Network::Nightly;

pub fn main() {
    let storage = ZkStorage::new();

    let guest = SP1Guest::new();

    let da_verifier = MockDaVerifier {};

    let input = guest.read_from_host();

    let lcp = LightClientProofCircuit::<ZkStorage, MockDaSpec, SP1Guest>::new();

    let output = lcp
        .run_circuit(
            da_verifier,
            input,
            storage,
            NETWORK,
            risc0_cutoff(NETWORK),
            GENESIS_ROOT,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &BATCH_PROVER_DA_PUBLIC_KEY,
            &SEQUENCER_DA_PUBLIC_KEY,
            &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEYS,
        )
        .unwrap();

    guest.commit(&output);
}
