use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};

fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        println!("cargo:warning=Skipping guest build");
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        let out_dir = std::path::Path::new(&out_dir);
        let methods_path = out_dir.join("methods.rs");

        let elf = r#"
            pub const BITCOIN_DA_ELF: &[u8] = &[];
            pub const MOCK_DA_ELF: &[u8] = &[];
            pub const BITCOIN_DA_ID: [u32; 8] = [0u32; 8];
            pub const MOCK_DA_ID: [u32; 8] = [0u32; 8];
        "#;

        std::fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
    } else {
        let guest_pkg_to_options = get_guest_options();
        embed_methods_with_options(guest_pkg_to_options);
    }
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
    guest_pkg_to_options
}
