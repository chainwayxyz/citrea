#![no_main]
use citrea_light_client_prover::circuit::run_circuit;
use sov_mock_da::MockDaVerifier;
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = MockDaVerifier {};

    let output = run_circuit::<MockDaVerifier, Risc0Guest>(da_verifier, &guest).unwrap();

    guest.commit(&output);
}
