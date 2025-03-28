use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD_LATEST");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=CITREA_NETWORK");
    println!("cargo:rerun-if-env-changed=SEQUENCER_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SEQUENCER_DA_PUB_KEY");

    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");
    if let Ok("1" | "true") = std::env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    match std::env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = std::env::var_os("OUT_DIR").unwrap();
                let out_dir = std::path::Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");

                let elf = r#"
                pub const BATCH_PROOF_BITCOIN_ELF: &[u8] = &[];
                pub const BATCH_PROOF_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const BATCH_PROOF_MOCK_ELF: &[u8] = &[];
                pub const BATCH_PROOF_MOCK_ID: [u32; 8] = [0u32; 8];
                "#;

                return std::fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
            }
            "0" | "false" => {
                println!("cargo:warning=Performing guest build");
            }
            _ => {
                println!("cargo:warning=Invalid value for SKIP_GUEST_BUILD: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to performing guest build.", value);
            }
        },
        Err(std::env::VarError::NotPresent) => {
            println!(
                "cargo:warning=SKIP_GUEST_BUILD not set. Defaulting to performing guest build."
            );
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            println!("cargo:warning=SKIP_GUEST_BUILD contains invalid Unicode. Defaulting to performing guest build.");
        }
    }
    let guest_pkg_to_options = get_guest_options();
    embed_methods_with_options(guest_pkg_to_options);
}

fn get_guest_options() -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let mut features = Vec::new();

    if std::env::var("CARGO_FEATURE_TESTING").is_ok() {
        println!("cargo:warning=Building with testing feature");
        features.push("testing".to_string());
    }

    let opts = if std::env::var("REPR_GUEST_BUILD_LATEST").is_ok() {
        let this_package_dir = std::env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{this_package_dir}/../../../");

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .build()
            .unwrap();

        GuestOptionsBuilder::default()
            .features(features)
            .use_docker(docker_opts)
            .build()
            .unwrap()
    } else {
        println!("cargo:warning=Guest code is not built in docker");

        GuestOptionsBuilder::default()
            .features(features)
            .build()
            .unwrap()
    };

    guest_pkg_to_options.insert("batch-proof-bitcoin", opts.clone());
    guest_pkg_to_options.insert("batch-proof-mock", opts.clone());
    guest_pkg_to_options
}
