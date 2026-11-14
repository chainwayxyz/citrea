#![cfg(feature = "native")]

use std::path::Path;

use sov_rollup_interface::zk::sp1::groth16_program_id;
use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};

/// Check the CLI decoder against the actual SDK keys.
#[allow(dead_code)]
mod guest_build {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    include!("../../../guests/sp1/build_guest.rs");
}

// Every pinned guest version, as in bin/citrea/src/guests.rs.
#[path = "../../../resources/guests/sp1/devnet/batch-proof-0.rs"]
mod devnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/devnet/light-client-proof-0.rs"]
mod devnet_light_client_proof_0;
#[path = "../../../resources/guests/sp1/mainnet/batch-proof-0.rs"]
mod mainnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/mainnet/light-client-proof-0.rs"]
mod mainnet_light_client_proof_0;
#[path = "../../../resources/guests/sp1/testnet/batch-proof-0.rs"]
mod testnet_batch_proof_0;
#[path = "../../../resources/guests/sp1/testnet/light-client-proof-0.rs"]
mod testnet_light_client_proof_0;

#[tokio::test]
async fn pinned_method_ids_match_sp1_hash_u32() {
    let pins = [
        (devnet_batch_proof_0::ELF, devnet_batch_proof_0::ID),
        (
            devnet_light_client_proof_0::ELF,
            devnet_light_client_proof_0::ID,
        ),
        (mainnet_batch_proof_0::ELF, mainnet_batch_proof_0::ID),
        (
            mainnet_light_client_proof_0::ELF,
            mainnet_light_client_proof_0::ID,
        ),
        (testnet_batch_proof_0::ELF, testnet_batch_proof_0::ID),
        (
            testnet_light_client_proof_0::ELF,
            testnet_light_client_proof_0::ID,
        ),
    ];

    // A pin that is committed but not listed above would go unchecked.
    let pinned = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../resources/guests/sp1");
    let pinned_elfs = ["devnet", "mainnet", "testnet"]
        .iter()
        .flat_map(|network| std::fs::read_dir(pinned.join(network)).unwrap())
        .filter(|entry| entry.as_ref().unwrap().path().extension() == Some("elf".as_ref()))
        .count();
    assert_eq!(pins.len(), pinned_elfs);

    let client = ProverClient::builder().mock().build().await;
    for (elf, expected) in pins {
        let pk = client.setup(elf.into()).await.unwrap();
        let vk = pk.verifying_key();
        assert_eq!(vk.hash_u32(), expected);
        assert_eq!(guest_build::native_program_id(&vk.bytes32()), expected);
        assert_eq!(groth16_program_id(&expected).unwrap(), vk.bytes32_raw());
    }
}
