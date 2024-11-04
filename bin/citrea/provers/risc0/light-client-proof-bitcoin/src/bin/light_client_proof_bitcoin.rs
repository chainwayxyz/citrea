#![no_main]
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::run_circuit;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
    });

    let output = run_circuit::<BitcoinVerifier, Risc0Guest>(da_verifier, &guest).unwrap();

    guest.commit(&output);
}
