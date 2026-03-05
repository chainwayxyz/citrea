#![no_main]
use citrea_light_client_prover::circuit::initial_values::mockda::{
    ALLOWED_PREVIOUS_LCP_METHOD_IDS, EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME, GENESIS_ROOT,
    INITIAL_BATCH_PROOF_METHOD_IDS, INITIAL_BATCH_PROVER_DA_PUBLIC_KEY,
    INITIAL_SECURITY_COUNCIL_THRESHOLD, INITIAL_SEQUENCER_DA_PUBLIC_KEY,
    METHOD_ID_UPGRADE_AUTHORITY_INITIAL_DA_ADDRESSES,
};
use citrea_light_client_prover::circuit::LightClientProofCircuit;
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_mock_da::{MockDaSpec, MockDaVerifier};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = Network::Nightly;

pub fn main() {
    let storage = ZkStorage::new();

    let guest = Risc0Guest::new();

    let da_verifier = MockDaVerifier {};

    let input = guest.read_from_host();

    let lcp = LightClientProofCircuit::<ZkStorage, MockDaSpec, Risc0Guest>::new();

    let output = lcp
        .run_circuit(
            da_verifier,
            input,
            storage,
            NETWORK,
            GENESIS_ROOT,
            INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
            &INITIAL_BATCH_PROVER_DA_PUBLIC_KEY,
            &INITIAL_SEQUENCER_DA_PUBLIC_KEY,
            METHOD_ID_UPGRADE_AUTHORITY_INITIAL_DA_ADDRESSES.inner(),
            INITIAL_SECURITY_COUNCIL_THRESHOLD,
            EIP712_SECURITY_COUNCIL_MESSAGE_DOMAIN_NAME.to_string(),
            ALLOWED_PREVIOUS_LCP_METHOD_IDS,
        )
        .unwrap();

    guest.commit(&output);
}
