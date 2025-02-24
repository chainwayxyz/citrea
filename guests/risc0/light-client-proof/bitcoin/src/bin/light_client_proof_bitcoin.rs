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
    Some(network) => match Network::const_from_str(network) {
        Some(network) => network,
        None => panic!("Invalid CITREA_NETWORK value"),
    },
    None => Network::Nightly,
};

const L2_GENESIS_ROOT: [u8; 32] = {
    let hex_root = match NETWORK {
        Network::Mainnet => "0000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "58a10034aa034f1f675312fac7233375337a6b532fc598b560deb428a45f7b01",
        Network::Devnet => "a0849432201a14882f01eab2b806c465c231d140f9d632a6f7a0df50fd927606",
        Network::Nightly | Network::TestNetworkWithForks => match option_env!("L2_GENESIS_ROOT") {
            Some(hex_root) => hex_root,
            None => "2e5345a517a1fb3326ef8784830772585ab8a2e3fd2e4e2a1b92a01aacb273fb",
        },
    };

    match const_hex::const_decode_to_array(hex_root.as_bytes()) {
        Ok(root) => root,
        Err(_) => panic!("L2_GENESIS_ROOT must be valid 32-byte hex string"),
    }
};

const fn decode_to_u32_array(hex: &str) -> [u32; 8] {
    let bytes = const_hex::const_decode_to_array::<32>(hex.as_bytes());
    match bytes {
        Ok(decoded) => constmuck::cast(decoded),
        Err(_) => panic!("Invalid hex input"), // Replace with compile-time valid fallback if needed
    }
}

const INITIAL_BATCH_PROOF_METHOD_IDS: &[(u64, [u32; 8])] = {
    match NETWORK {
        // TODO: Update
        Network::Mainnet => &[(0, [0; 8])],
        Network::Testnet => &[
            (
                0,
                decode_to_u32_array(
                    "3631d90630a3f0deb47f3a3411fe6e7ede1b0d86ad4216c75041e1a2020f009f",
                ),
            ),
            (
                5546000,
                decode_to_u32_array(
                    "14d26c6b8cd8553c5613b359c8b313a08a2a17b0174a3471d32fd7c1323e6279",
                ),
            ),
        ],
        Network::Devnet => &[
            (
                0,
                decode_to_u32_array(
                    "3631d90630a3f0deb47f3a3411fe6e7ede1b0d86ad4216c75041e1a2020f009f",
                ),
            ),
            (
                1921835,
                decode_to_u32_array(
                    "a6a660040f9161ddac7c4a401b8aa0a01c09802fd099aa6c143bf8c18c69a55f",
                ),
            ),
        ],
        Network::Nightly | Network::TestNetworkWithForks => {
            match option_env!("BATCH_PROOF_METHOD_ID") {
                Some(hex_method_id) => &[(0, decode_to_u32_array(hex_method_id))],
                None => &[
                    (
                        0,
                        decode_to_u32_array(
                            "382a4e434d1b4b0912604a9de8876e75ff7603680c90107d78f6f71784ef1922",
                        ),
                    ),
                    (
                        100,
                        decode_to_u32_array(
                            "c8c204ecbc23bdf4794a8e9065c8cbd96f282acb97f6924116c51141c08b86dc",
                        ),
                    ),
                    (200, citrea_risc0_batch_proof::BATCH_PROOF_BITCOIN_ID),
                ],
            }
        }
    }
};

const BATCH_PROVER_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "030000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42",
        Network::Devnet => "03fc6fb2ef68368009c895d2d4351dcca4109ec2f5f327291a0553570ce769f5e5",
        Network::Nightly | Network::TestNetworkWithForks => {
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

pub const METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "000000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "03796a3a8a86ff1cc37437585f0450f6059c397c01bce06bfbaaa36242f7ebfc02",
        Network::Devnet => "0388e988066db18e19750fa92aa0fbf9c85104be2b5b507ce0aa7f30f3fe24b1ac",
        Network::Nightly | Network::TestNetworkWithForks => {
            match option_env!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "0313c4ff65eb94999e0ac41cfe21592baa52910f5a5ada9074b816de4f560189db",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => {
            panic!("METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY must be valid 33-byte hex string")
        }
    }
};

pub fn main() {
    let guest = Risc0Guest::new();

    let da_verifier = BitcoinVerifier::new(RollupParams {
        to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
        to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
    });

    let input = guest.read_from_host();

    let output = run_circuit::<BitcoinVerifier, Risc0Guest>(
        da_verifier,
        input,
        L2_GENESIS_ROOT,
        INITIAL_BATCH_PROOF_METHOD_IDS.to_vec(),
        &BATCH_PROVER_DA_PUBLIC_KEY,
        &METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY,
        NETWORK,
    )
    .unwrap();

    guest.commit(&output);
}
