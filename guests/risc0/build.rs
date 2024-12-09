use std::collections::HashMap;
use std::path::Path;
use std::{env, fs};

use risc0_build::{embed_methods_with_options, GuestOptions};

fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    println!("cargo:rerun-if-changed=Dockerfile");

    match env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = env::var_os("OUT_DIR").unwrap();
                let out_dir = Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");

                let elf = r#"
                pub const BATCH_PROOF_BITCOIN_ELF: &[u8] = &[];
                pub const BATCH_PROOF_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const BATCH_PROOF_MOCK_ELF: &[u8] = &[];
                pub const BATCH_PROOF_MOCK_ID: [u32; 8] = [0u32; 8];
                pub const LIGHT_CLIENT_PROOF_BITCOIN_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_PROOF_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const LIGHT_CLIENT_PROOF_MOCK_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_PROOF_MOCK_ID: [u32; 8] = [0u32; 8];
                "#;

                return fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
            }
            "0" | "false" => {
                println!("cargo:warning=Performing guest build");
            }
            _ => {
                println!("cargo:warning=Invalid value for SKIP_GUEST_BUILD: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to performing guest build.", value);
            }
        },
        Err(env::VarError::NotPresent) => {
            println!(
                "cargo:warning=SKIP_GUEST_BUILD not set. Defaulting to performing guest build."
            );
        }
        Err(env::VarError::NotUnicode(_)) => {
            println!("cargo:warning=SKIP_GUEST_BUILD contains invalid Unicode. Defaulting to performing guest build.");
        }
    }

    if env::var("REPR_GUEST_BUILD").is_ok() {
        repr_build();
    } else {
        build();
    }
}

fn build() {
    println!("cargo:warning=Guest code is not built in docker");

    let mut guest_pkg_to_options = HashMap::new();

    let mut features = Vec::new();
    if std::env::var("CARGO_FEATURE_SHORT_PREFIX").is_ok() {
        features.push("short-prefix".to_string());
    }

    let opts = GuestOptions {
        features,
        use_docker: None,
    };

    guest_pkg_to_options.insert("batch-proof-bitcoin", opts.clone());
    guest_pkg_to_options.insert("batch-proof-mock", opts.clone());
    guest_pkg_to_options.insert("light-client-proof-bitcoin", opts.clone());
    guest_pkg_to_options.insert("light-client-proof-mock", opts);

    embed_methods_with_options(guest_pkg_to_options);
}

fn repr_build() {
    unimplemented!()
}
