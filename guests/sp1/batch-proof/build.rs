use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

fn main() {
    // The light-client guests include only the batch program IDs, see src/lib.rs.
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "zkvm" {
        return;
    }
    for name in [
        "SKIP_GUEST_BUILD",
        "REPR_GUEST_BUILD",
        // Compile-time guest inputs
        "CITREA_NETWORK",
        "SEQUENCER_PUBLIC_KEY",
        "INITIAL_PREV_L2_BLOCK_HASH",
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

    let mut methods = String::new();
    for da in ["bitcoin", "mock"] {
        methods += &build_guest("BATCH_PROOF", da);
    }
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("methods.rs"),
        methods,
    )
    .unwrap();
}

include!("../build_guest.rs");
