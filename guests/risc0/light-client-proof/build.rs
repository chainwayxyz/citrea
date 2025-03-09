use std::collections::HashMap;
use std::thread;

use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD_LATEST");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=CITREA_NETWORK");
    println!("cargo:rerun-if-env-changed=L2_GENESIS_ROOT");
    println!("cargo:rerun-if-env-changed=BATCH_PROOF_METHOD_ID");
    println!("cargo:rerun-if-env-changed=PROVER_DA_PUB_KEY");

    match std::env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = std::env::var_os("OUT_DIR").unwrap();
                let out_dir = std::path::Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");

                let elf = r#"
                pub const LIGHT_CLIENT_PROOF_BITCOIN_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_PROOF_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const LIGHT_CLIENT_PROOF_MOCK_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_PROOF_MOCK_ID: [u32; 8] = [0u32; 8];
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

    let guests = ["light-client-proof-bitcoin", "light-client-proof-mock"];
    let mut handles = vec![];
    for guest in guests {
        let handle = thread::spawn(move || {
            let guest_pkg_to_options = get_guest_options(guest);
            (
                guest,
                embed_methods_with_options(guest_pkg_to_options)
                    .pop()
                    .expect("At least one guest entry should be set"),
            )
        });
        handles.push(handle);
    }
    let mut guest_entries = HashMap::new();
    for handle in handles {
        let (name, guest_entry) = handle.join().expect("Building guest should not fail");
        guest_entries.insert(name, guest_entry);
    }
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_dir = std::path::Path::new(&out_dir);
    let methods_path = out_dir.join("methods.rs");

    let bitcoin_guest = guest_entries
        .get("light-client-proof-bitcoin")
        .expect("light-client-proof-bitcoin guest should be present");
    let mock_guest = guest_entries
        .get("light-client-proof-mock")
        .expect("light-client-proof-mock guest should be present");

    let bitcoin_elf_path = format!("{:?}", bitcoin_guest.path);
    let bitcoin_image_id = format!("{:?}", bitcoin_guest.image_id);
    let mock_elf_path = format!("{:?}", mock_guest.path);
    let mock_image_id = format!("{:?}", mock_guest.image_id);

    let elf = format!(
        r#"
    pub const LIGHT_CLIENT_PROOF_BITCOIN_ELF: &[u8] = include_bytes!({bitcoin_elf_path});
    pub const LIGHT_CLIENT_PROOF_BITCOIN_PATH: &str = {bitcoin_elf_path};
    pub const LIGHT_CLIENT_PROOF_BITCOIN_ID: [u32; 8] = {bitcoin_image_id};

    pub const LIGHT_CLIENT_PROOF_MOCK_ELF: &[u8] = include_bytes!({mock_elf_path});
    pub const LIGHT_CLIENT_PROOF_MOCK_PATH: &str = {mock_elf_path};
    pub const LIGHT_CLIENT_PROOF_MOCK_ID: [u32; 8] = {mock_image_id};
    "#
    );
    println!("Writing to methods path: {:?}", methods_path);
    std::fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
}

fn get_guest_options(
    guest_to_build: &'static str,
) -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let mut features = Vec::new();

    if std::env::var("CARGO_FEATURE_TESTING").is_ok() {
        features.push("testing".to_string());
    }

    let use_docker = if std::env::var("REPR_GUEST_BUILD_LATEST").is_ok() {
        let this_package_dir = std::env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{this_package_dir}/../../../");
        Some(DockerOptions {
            root_dir: Some(root_dir.into()),
        })
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        None
    };

    let opts = GuestOptions {
        features,
        use_docker,
    };

    guest_pkg_to_options.insert(guest_to_build, opts.clone());
    guest_pkg_to_options
}
