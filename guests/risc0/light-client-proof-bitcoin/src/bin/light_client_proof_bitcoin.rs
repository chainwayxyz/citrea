#![no_main]
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::run_circuit;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = match option_env!("CITREA_NETWORK") {
    Some(network) => {
        match Network::const_from_str(network) {
            Some(network) => network,
            None => panic!("Invalid CITREA_NETWORK value"),
        } 
    }
    None => Network::Nightly,
};

// TODO: Find l2 genesis roots of networks
const L2_GENESIS_ROOT: [u8; 32] = {
    let hex_root = match NETWORK {
        Network::Mainnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Devnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Nightly => {
            match option_env!("L2_GENESIS_ROOT") {
                Some(hex_root) => hex_root,
                None => "0000000000000000000000000000000000000000000000000000000000000000",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_root.as_bytes()) {
        Ok(root) => root,
        Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
    }
};

// TODO: Find batch proof method ids of networks
const BATCH_PROOF_METHOD_ID: [u32; 8] = {
    let hex_method_id = match NETWORK {
        Network::Mainnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Devnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Nightly => {
            match option_env!("BATCH_PROOF_METHOD_ID") {
                Some(hex_root) => hex_root,
                None => "0000000000000000000000000000000000000000000000000000000000000000",
            }
        }
    };

    match const_hex::const_decode_to_array::<32>(hex_method_id.as_bytes()) {
        Ok(method_id) => constmuck::cast(method_id),
        Err(_) => panic!("BATCH_PROOF_METHOD_ID must be valid 32-byte hex string"),
    }
};

const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        // TODO: Update mainnet pub key
        Network::Mainnet => "0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42",
        Network::Testnet => "0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42",
        Network::Devnet => "03fc6fb2ef68368009c895d2d4351dcca4109ec2f5f327291a0553570ce769f5e5",
        Network::Nightly => {
            match option_env!("PROVER_DA_PUB_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "03eedab888e45f3bdc3ec9918c491c11e5cf7af0a91f38b97fbc1e135ae4056601",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("PROVER_DA_PUB_KEY must be valid 33-byte hex string"),
    }
};

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
    });

    let input = guest.read_from_host();

    let output = run_circuit::<BitcoinVerifier, Risc0Guest>(da_verifier, input, L2_GENESIS_ROOT, BATCH_PROOF_METHOD_ID, &BATCH_PROVER_DA_PUBLIC_KEY).unwrap();

    guest.commit(&output);
}
