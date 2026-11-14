// KoalaBear field modulus; native SP1 key-digest words must be smaller than this.
// Pinned upstream modulus: https://github.com/Plonky3/Plonky3/blob/5309d4d0975d260f414ea98cf47456299971927a/koala-bear/src/koala_bear.rs#L19
const KOALABEAR_P: u32 = 0x7f00_0001;

/// Builds the guest in `da/` and returns its ELF and program ID constants.
fn build_guest(prefix: &str, da: &str) -> String {
    let constant = format!("{prefix}_{}", da.to_uppercase());
    if matches!(env::var("SKIP_GUEST_BUILD").as_deref(), Ok("1" | "true")) {
        return format!(
            "pub const {constant}_ELF: &[u8] = &[];\npub const {constant}_ID: [u32; 8] = [0; 8];\n"
        );
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../..")
        .canonicalize()
        .unwrap();
    let out = env::var("OUT_DIR").unwrap();
    let target = root.join("guests/sp1/target");
    // Create these as the host user, or rootful Docker creates them as root. The light-client
    // build script writes batch-proof-ids.rs into target, and native guest builds write into
    // sp1-build's elf-compilation cache (Docker builds use its docker/ subdirectory):
    // https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/build/src/lib.rs#L18
    std::fs::create_dir_all(target.join("elf-compilation")).unwrap();
    let elf_name = format!("{prefix}-{da}.elf");
    // `cargo prove build --locked` does not protect the lockfile: sp1-build first runs
    // `cargo metadata` without --locked, which silently rewrites a stale Cargo.lock.
    assert!(
        Command::new("cargo")
            .current_dir(da)
            .args(["+1.96.0", "metadata", "--locked", "--format-version", "1"])
            .stdout(std::process::Stdio::null())
            .status()
            .expect("Install SP1 6.10.0 with make install-sp1")
            .success(),
        "Stale guest Cargo.lock, see the error above. Update it by running \
         `cargo +1.96.0 metadata --format-version 1 > /dev/null` in its directory, then commit it."
    );
    let mut build = Command::new("cargo");
    build
        .current_dir(da)
        .args([
            "+1.96.0",
            "prove",
            "build",
            "--locked",
            "--output-directory",
        ])
        .args([&out, "--elf-name", &elf_name])
        // The succinct 1.96.0 rustc still has the SimplifyComparisonIntegral miscompilation
        // that Rust 1.96.1 fixed: https://github.com/rust-lang/rust/issues/158206
        // Disable the pass in both build modes until SP1 ships a fixed toolchain. SP1 appends
        // repeated --rustflags to its own flags for every crate, std excluded (it is prebuilt):
        // https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/build/src/command/utils.rs#L83
        .arg("--rustflags=-Zmir-enable-passes=-SimplifyComparisonIntegral")
        // One cache for all guests, inside the directory that Docker builds mount.
        .env("CARGO_TARGET_DIR", &target);
    if env::var_os("CARGO_FEATURE_TESTING").is_some() {
        build.args(["--features", "testing"]);
    }
    if matches!(env::var("REPR_GUEST_BUILD").as_deref(), Ok("1" | "true")) {
        let network =
            env::var("CITREA_NETWORK").expect("CITREA_NETWORK must be set in docker build!");
        assert!(
            matches!(
                network.as_str(),
                "mainnet" | "testnet" | "devnet" | "nightly"
            ),
            "Invalid CITREA_NETWORK value: {network}",
        );
        // The guests depend on crates outside their own workspaces.
        build
            .args(["--docker", "--tag", "v6.10.0", "--workspace-directory"])
            .arg(&root)
            // SP1 does not forward the environment into Docker.
            // https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/build/src/command/docker.rs#L188-L215
            .arg(format!(
                "--rustflags=-Zunstable-options,--env-set,CITREA_NETWORK={network}"
            ));
    }
    assert!(
        build
            .status()
            .expect("Install SP1 6.10.0 with make install-sp1")
            .success(),
        "SP1 guest build failed"
    );
    let elf = Path::new(&out).join(elf_name);
    let output = Command::new("cargo")
        .args(["prove", "vkey", "--elf"])
        .arg(&elf)
        .env("SP1_PROVER", "mock")
        .output()
        .expect("Install SP1 6.10.0 with make install-sp1");
    assert!(
        output.status.success(),
        "SP1 program key derivation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = stdout
        .lines()
        .find(|line| line.starts_with("0x") && line.len() == 66)
        .expect("Missing SP1 program key");
    let id = native_program_id(key);
    format!("pub const {constant}_ELF: &[u8] = include_bytes!({elf:?});\npub const {constant}_ID: [u32; 8] = {id:?};\n")
}

/// Recover `HashableKey::hash_u32()` from the CLI's lossless base-2^31 BN254 packing.
///
/// Inverse of SP1 6.10.0's [koalabears_to_bn254], decoding the [CLI vkey output].
/// The inverse is specific to this adapter; SP1 only supplies the forward conversion.
/// `crates/sovereign-sdk/rollup-interface/tests/program_ids.rs` checks the CLI fixture;
/// `crates/sp1/tests/native_keys.rs` compares the result with the SDK's native digest.
///
/// [koalabears_to_bn254]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/hypercube/src/verifier/hashable_key.rs#L20-L32
/// [CLI vkey output]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/cli/src/commands/vkey.rs#L47-L60
pub(crate) fn native_program_id(key: &str) -> [u32; 8] {
    let packed: [u32; 8] = std::array::from_fn(|i| {
        u32::from_str_radix(&key[2 + 8 * i..10 + 8 * i], 16).expect("Invalid SP1 program key")
    });
    assert_eq!(packed[0] >> 24, 0, "SP1 program key exceeds 248 bits");
    let words = std::array::from_fn(|i| {
        let pair = (u64::from(packed[i]) << 32)
            | u64::from(packed.get(i + 1).copied().unwrap_or_default());
        ((pair >> (25 + i)) & 0x7fff_ffff) as u32
    });
    assert!(
        words.iter().all(|&word| word < KOALABEAR_P),
        "Noncanonical SP1 program key"
    );
    words
}
