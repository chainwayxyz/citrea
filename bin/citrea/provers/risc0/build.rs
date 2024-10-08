use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};

fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    match std::env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = std::env::var_os("OUT_DIR").unwrap();
                let out_dir = std::path::Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");

                let elf = r#"
                pub const BITCOIN_DA_ELF: &[u8] = &[];
                pub const MOCK_DA_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_BITCOIN_DA_ELF: &[u8] = &[];
                pub const LIGHT_CLIENT_MOCK_DA_ELF: &[u8] = &[];
                pub const BITCOIN_DA_ID: [u32; 8] = [0u32; 8];
                pub const MOCK_DA_ID: [u32; 8] = [0u32; 8];
<<<<<<< HEAD
                pub const LIGHT_CLIENT_BITCOIN_DA_ID: [u32; 8] = [0u32; 8];
                pub const LIGHT_CLIENT_MOCK_DA_ID: [u32; 8] = [0u32; 8];
=======
                pub const LIGHT_CLIENT_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const LIGHT_CLIENT_MOCK_ID: [u32; 8] = [0u32; 8];
>>>>>>> esad/light-client-starter
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
            println!("cargo:warning=SKIP_GUEST_BUILD not set. Performing guest build.");
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
    let mut features = vec![];

    if cfg!(feature = "bench") {
        features.push("bench".to_string());
    }
    let use_docker = if std::env::var("REPR_GUEST_BUILD").is_ok() {
        let this_package_dir = std::env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{this_package_dir}/../../../../");
        Some(DockerOptions {
            root_dir: Some(root_dir.into()),
        })
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        None
    };

    guest_pkg_to_options.insert(
        "sov-demo-prover-guest-mock",
        GuestOptions {
            features: features.clone(),
            use_docker: use_docker.clone(),
        },
    );
    guest_pkg_to_options.insert(
        "citrea-bitcoin-prover",
        GuestOptions {
            features: features.clone(),
            use_docker: use_docker.clone(),
        },
    );
    guest_pkg_to_options.insert(
        "citrea-light-client-bitcoin",
        GuestOptions {
            features: features.clone(),
            use_docker: use_docker.clone(),
        },
    );
    guest_pkg_to_options.insert(
        "citrea-light-client-mock",
        GuestOptions {
            features: features.clone(),
            use_docker: use_docker.clone(),
        },
    );
    guest_pkg_to_options
}
