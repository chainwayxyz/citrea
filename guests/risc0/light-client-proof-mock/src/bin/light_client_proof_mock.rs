#![no_main]
use citrea_light_client_prover::circuit::run_circuit;
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_mock_da::MockDaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;

risc0_zkvm::guest::entry!(main);

const L2_GENESIS_ROOT: [u8; 32] = {
    let hex_root = env!("L2_GENESIS_ROOT");

    match const_hex::const_decode_to_array(hex_root.as_bytes()) {
        Ok(root) => root,
        Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
    }
};

const BATCH_PROOF_METHOD_ID: [u32; 8] = {
    let hex_method_id = env!("BATCH_PROOF_METHOD_ID");

    match const_hex::const_decode_to_array::<32>(hex_method_id.as_bytes()) {
        Ok(method_id) => constmuck::cast(method_id),
        Err(_) => panic!("BATCH_PROOF_METHOD_ID must be valid 32-byte hex string"),
    }
};

const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = env!("BATCH_PROVER_DA_PUBLIC_KEY");

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => {
            if pub_key[0] != 2 && pub_key[0] != 3 {
                panic!("BATCH_PROVER_DA_PUBLIC_KEY first byte must be either 02 or 03");
            }
            pub_key
        }
        Err(_) => panic!("BATCH_PROVER_DA_PUBLIC_KEY must be valid 33-byte hex string"),
    }
};

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = MockDaVerifier {};

    let input = guest.read_from_host();

    let output = run_circuit::<MockDaVerifier, Risc0Guest>(da_verifier, input, L2_GENESIS_ROOT, BATCH_PROOF_METHOD_ID, &BATCH_PROVER_DA_PUBLIC_KEY).unwrap();

    guest.commit(&output);
}
