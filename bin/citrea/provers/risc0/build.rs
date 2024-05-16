use std::collections::HashMap;

fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    if std::env::var("SKIP_GUEST_BUILD").is_ok() {
        println!("Skipping guest build for CI run");
        let out_dir = std::env::var_os("OUT_DIR").unwrap();
        let out_dir = std::path::Path::new(&out_dir);
        let methods_path = out_dir.join("methods.rs");

        let elf = r#"
            pub const BITCOIN_DA_ELF: &[u8] = &[];
            pub const MOCK_DA_ELF: &[u8] = &[];
        "#;

        std::fs::write(methods_path, elf).expect("Failed to write mock rollup elf");
    } else {
        let guest_pkg_to_options = get_guest_options();
        risc0_build::embed_methods_with_options(guest_pkg_to_options);
    }
}

fn get_guest_options() -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();
    let mut features = vec![];

    if cfg!(feature = "bench") {
        features.push("bench".to_string());
    }
    guest_pkg_to_options.insert(
        "sov-demo-prover-guest-mock",
        risc0_build::GuestOptions {
            features,
            ..Default::default()
        },
    );
    guest_pkg_to_options
}
