use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() {
    for name in [
        "SKIP_GUEST_BUILD",
        "REPR_GUEST_BUILD",
        // Compile-time guest inputs
        "CITREA_NETWORK",
        "L2_GENESIS_ROOT",
        "BATCH_PROOF_METHOD_ID",
        "PROVER_DA_PUB_KEY",
        "SEQUENCER_DA_PUB_KEY",
        "METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY_1",
        "METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY_2",
        "METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY_3",
        "METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY_4",
        "METHOD_ID_UPGRADE_AUTHORITY_DA_PUBLIC_KEY_5",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    for path in [
        "bitcoin",
        "mock",
        "../.cargo/config.toml",
        "../../../crates",
        "../../../Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    // The guests include the batch program IDs from this file, see
    // guests/sp1/batch-proof/src/lib.rs.
    let ids = format!(
        "pub const BATCH_PROOF_BITCOIN_ID: [u32; 8] = {:?};\npub const BATCH_PROOF_MOCK_ID: [u32; 8] = {:?};\n",
        citrea_sp1_batch_proof::BATCH_PROOF_BITCOIN_ID,
        citrea_sp1_batch_proof::BATCH_PROOF_MOCK_ID,
    );
    let path = Path::new("../target/batch-proof-ids.rs");
    if !matches!(env::var("SKIP_GUEST_BUILD").as_deref(), Ok("1" | "true"))
        && fs::read_to_string(path).ok().as_deref() != Some(ids.as_str())
    {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, ids).unwrap();
    }

    let mut methods = String::new();
    for da in ["bitcoin", "mock"] {
        methods += &build_guest("LIGHT_CLIENT_PROOF", da);
    }
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("methods.rs"),
        methods,
    )
    .unwrap();
}

include!("../build_guest.rs");
