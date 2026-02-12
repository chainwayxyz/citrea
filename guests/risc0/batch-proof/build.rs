use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::{env, fs, path};

use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};

fn get_cache_path() -> PathBuf {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR missing"));
    let target_dir = out_dir
        .ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new("target")))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));

    target_dir.join(".method_ids_cache.txt")
}

fn testing_enabled() -> bool {
    matches!(env::var("CARGO_FEATURE_TESTING").as_deref(), Ok("1" | "true"))
}

fn cache_method_ids() {
    if !testing_enabled() {
        return;
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let methods_path = path::Path::new(&out_dir).join("methods.rs");
    if !methods_path.exists() {
        return;
    }

    let cache_path = get_cache_path();
    println!("cargo:warning=Setting method ids cache at path: {cache_path:?}");

    fs::copy(methods_path, cache_path).ok();
}

fn use_cached_method_ids() -> bool {
    if !testing_enabled() {
        return false;
    }

    let cache_path = get_cache_path();
    println!("cargo:warning=Using cache at path: {cache_path:?}");
    if !cache_path.exists() {
        return false;
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let methods_path = path::Path::new(&out_dir).join("methods.rs");

    fs::copy(cache_path, methods_path).is_ok()
}

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");
    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=CITREA_NETWORK");
    println!("cargo:rerun-if-env-changed=SEQUENCER_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=SEQUENCER_DA_PUB_KEY");

    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");
    if let Ok("1" | "true") = env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    match env::var("SKIP_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=Skipping guest build");
                let out_dir = env::var_os("OUT_DIR").unwrap();
                let out_dir = path::Path::new(&out_dir);
                let methods_path = out_dir.join("methods.rs");

                let elf = r#"
                pub const BATCH_PROOF_BITCOIN_ELF: &[u8] = &[];
                pub const BATCH_PROOF_BITCOIN_ID: [u32; 8] = [0u32; 8];
                pub const BATCH_PROOF_MOCK_ELF: &[u8] = &[];
                pub const BATCH_PROOF_MOCK_ID: [u32; 8] = [0u32; 8];
                "#;

                return fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
            }
            "0" | "false" => {
                println!("cargo:warning=Performing guest build");
            }
            _ => {
                println!(
                    "cargo:warning=Invalid value for SKIP_GUEST_BUILD: '{value}'. Expected '0'
, '1', 'true', or 'false'. Defaulting to performing guest build."
                );
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

    // When compiled as a riscv dependency (inside light-client guest build),
    // use cached method IDs instead of rebuilding.
    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:warning=Target {target}");
    if target.contains("riscv") {
        if use_cached_method_ids() {
            println!("cargo:warning=Using cached method IDs for riscv target: {target}");
            return;
        }
        println!("cargo:warning=No method ID cache, rebuilding for riscv target: {target}");
    }

    let guest_pkg_to_options = get_guest_options();
    embed_methods_with_options(guest_pkg_to_options);

    // Cache method IDs for reuse when building as a riscv dependency.
    cache_method_ids();
}

fn get_guest_options() -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let mut features = Vec::new();

    if testing_enabled() {
        println!("cargo:warning=Building with testing feature");
        features.push("testing".to_string());
    }

    let opts = if env::var("REPR_GUEST_BUILD").is_ok() {
        let network =
            env::var("CITREA_NETWORK").expect("CITREA_NETWORK must be set in docker build!");
        assert!(
            matches!(
                network.as_str(),
                "mainnet" | "testnet" | "devnet" | "nightly"
            ),
            "Invalid CITREA_NETWORK value: {network}",
        );

        println!("cargo:warning=Building guest in docker with network {network}");

        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let root_dir = format!("{manifest_dir}/../../../");

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .env(vec![("CITREA_NETWORK".to_string(), network)])
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
    guest_pkg_to_options.insert("batch-proof-mock", opts);

    guest_pkg_to_options
}
