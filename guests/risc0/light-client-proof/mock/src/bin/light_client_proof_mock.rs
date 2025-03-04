#![no_main]
use citrea_light_client_prover::circuit::old::run_circuit;
use citrea_light_client_prover::circuit::primitives::mockda::{
    BATCH_PROVER_DA_PUBLIC_KEY, GENESIS_ROOT, INITIAL_BATCH_PROOF_METHOD_IDS,
    METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
};
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_mock_da::MockDaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = Network::Nightly;

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = MockDaVerifier {};

    let input = guest.read_from_host();

    let output = run_circuit::<MockDaVerifier, Risc0Guest>(
        da_verifier,
        input,
        GENESIS_ROOT,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &BATCH_PROVER_DA_PUBLIC_KEY,
        &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        NETWORK,
    )
    .unwrap();

    guest.commit(&output);
}
