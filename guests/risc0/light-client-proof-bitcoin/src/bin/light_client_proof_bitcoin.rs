#![no_main]
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::run_circuit;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

const L2_GENESIS_ROOT: [u8; 32] = match option_env!("L2_GENESIS_ROOT") {
    Some(hex_root) => {
        match const_hex::const_decode_to_array(hex_root.as_bytes()) {
            Ok(root) => root,
            Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
        }
    }
    // TODO: what to do here?
    None => [0; 32],
};

const BATCH_PROOF_METHOD_ID: [u8; 32] = match option_env!("BATCH_PROOF_METHOD_ID") {
    Some(hex_method_id) => {
        match const_hex::const_decode_to_array(hex_method_id.as_bytes()) {
            Ok(method_id) => method_id,
            Err(_) => panic!("BATCH_PROOF_METHOD_ID must be valid 32-byte hex string"),
        }
    }
    // TODO: what to do here?
    None => [0; 32],
};

const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = match option_env!("BATCH_PROVER_DA_PUBLIC_KEY") {
    Some(hex_pub_key) => {
        match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
            Ok(pub_key) => pub_key,
            Err(_) => panic!("BATCH_PROVER_DA_PUBLIC_KEY must be valid 33-byte hex string"),
        }
    }
    // TODO: what to do here?
    None => [0; 33],
};

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
    });

    let input = guest.read_from_host();

    let output = run_circuit::<BitcoinVerifier, Risc0Guest>(da_verifier, input).unwrap();

    guest.commit(&output);
}
