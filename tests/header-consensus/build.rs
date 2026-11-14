use std::{env, path::PathBuf, process::Command};

fn main() {
    extract_implementations();
    println!("cargo:rerun-if-env-changed=BITCOIN_CORE_SOURCE");
    println!("cargo:rerun-if-changed=core_oracle.cpp");
    let root = PathBuf::from(
        env::var_os("BITCOIN_CORE_SOURCE")
            .expect("Set BITCOIN_CORE_SOURCE to a clean Bitcoin Core v29.0 checkout"),
    );
    let commit = Command::new("git")
        .args(["-C", root.to_str().unwrap(), "rev-parse", "HEAD"])
        .output()
        .expect("git");
    assert!(commit.status.success());
    assert_eq!(
        String::from_utf8(commit.stdout).unwrap().trim(),
        "f490f5562d4b20857ef8d042c050763795fd43da",
        "Unexpected Bitcoin Core revision"
    );
    let diff = Command::new("git")
        .args([
            "-C",
            root.to_str().unwrap(),
            "diff",
            "HEAD",
            "--exit-code",
            "--",
            "src",
        ])
        .status()
        .expect("git diff");
    assert!(
        diff.success(),
        "Bitcoin Core oracle sources must be unchanged"
    );
    let src = root.join("src");
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++20")
        .flag("-Wno-unused-parameter")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .include(&src)
        .file("core_oracle.cpp");
    for file in ["arith_uint256.cpp", "uint256.cpp", "pow.cpp", "chain.cpp"] {
        println!("cargo:rerun-if-changed={}", src.join(file).display());
        build.file(src.join(file));
    }
    build.compile("bitcoin_core_oracle");
    println!("cargo:rustc-link-arg=-Wl,--gc-sections");
}

// Extract balanced, top-level function bodies from the supplied production files.
// Visibility is the only function change; no handwritten copy of the algorithms is tested.
fn function(source: &str, name: &str) -> String {
    let needle = format!("fn {name}(");
    let start = source.find(&needle).expect(name);
    let brace = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (i, byte) in source[brace..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => (),
        }
        if depth == 0 {
            return format!("pub {}\n", &source[start..=brace + i]);
        }
    }
    panic!("Unclosed function {name}");
}

fn extract_implementations() {
    use std::fs;
    let here = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=CITREA_SOURCE");
    println!("cargo:rerun-if-env-changed=CLEMENTINE_SOURCE");
    let citrea = env::var_os("CITREA_SOURCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| here.join("../.."));
    let clementine = PathBuf::from(
        env::var_os("CLEMENTINE_SOURCE")
            .expect("Set CLEMENTINE_SOURCE to the Clementine checkout to test"),
    );
    let mut generated = String::new();
    for (name, root, path, work) in [
        (
            "citrea",
            citrea,
            "crates/bitcoin-da/src/verifier.rs",
            "target_to_work",
        ),
        (
            "clementine",
            clementine,
            "circuits-lib/src/header_chain/mod.rs",
            "calculate_work",
        ),
    ] {
        let path = root.join(path);
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(path).unwrap();
        for network in 0..3 {
            generated +=
                &format!("pub mod {name}_{network} {{\nuse crypto_bigint::{{Encoding,U256}};\n");
            if name == "clementine" {
                // Select the network as production does; retain the real constant
                // expressions for both the typed and environment-based configurations.
                let label = ["mainnet", "testnet4", "signet"][network];
                let start = source
                    .find("#[derive(Debug)]\npub struct NetworkConstants")
                    .unwrap();
                let end = source.find("/// Serializable representation").unwrap();
                if source.contains("BuildNetwork::") {
                    generated += "#[derive(Clone,Copy)] enum BuildNetwork { Mainnet, Testnet4, Signet, Regtest }\n";
                    generated += &format!(
                        "const BUILD_NETWORK: BuildNetwork = BuildNetwork::{};\n",
                        ["Mainnet", "Testnet4", "Signet"][network]
                    );
                    generated += &source[start..end];
                } else {
                    generated += &source[start..end]
                        .replace("get_network()", &format!("\"{label}\""))
                        .replace(
                            "option_env!(\"BITCOIN_NETWORK\")",
                            &format!("Some(\"{label}\")"),
                        );
                }
            }
            for helper in [
                "bits_to_target",
                "target_to_bits",
                work,
                "calculate_new_difficulty",
            ] {
                generated += &function(&source, helper);
            }
            if name == "citrea" {
                generated += &function(&source, "verify_timestamp");
                generated += &function(&source, "verify_target_hash");
            } else {
                generated += "use std::cmp::Ordering;\n";
                generated += &function(&source, "check_hash_valid");
                generated += &function(&source, "median");
                generated += &function(&source, "validate_timestamp");
                if source.contains("fn validate_header_timestamp(") {
                    generated += &function(&source, "validate_header_timestamp");
                } else if function(&source, "validate_timestamp")
                    .split('{')
                    .next()
                    .unwrap()
                    .contains("height: u32")
                {
                    generated += "pub use validate_timestamp as validate_header_timestamp;\n";
                } else {
                    // Migration branch calls validate_timestamp without considering height.
                    generated += "pub fn validate_header_timestamp(t:u32, times:[u32;11], _height:u32)->bool { validate_timestamp(t,times) }\n";
                }
            }
            generated += "}\n";
        }
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("production.rs"),
        generated,
    )
    .unwrap();
}
