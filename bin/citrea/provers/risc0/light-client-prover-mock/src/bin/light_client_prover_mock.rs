#![no_main]
use citrea_light_client_prover::circuit::run_circuit;
use citrea_light_client_prover::input::LightClientCircuitInput;
use sov_mock_da::{MockDaSpec, MockDaVerifier};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();

    let input: LightClientCircuitInput<MockDaSpec> = guest.read_from_host();

    let da_verifier = MockDaVerifier {};

    let output = run_circuit::<MockDaVerifier>(input, da_verifier).unwrap();

    guest.commit(&output);
}
