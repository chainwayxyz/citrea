// Generates a prefix for REVEAL_BATCH_PROOF_PREFIX and REVEAL_LIGHT_CLIENT_PREFIX constants based on compile-time environment.
// Returns a single-byte prefix [1] if SHORT_PREFIX env var is set, otherwise defaults to [1, 1].
// This greatly reduces the time required to find a nonce when generating batch proving txs and LightClientTxs
// We have to make these prefixes constants due to zk proving.
// But two bytes takes too long to generate nonce, making tests very flaky and slow.
// So in CI we define an env var SHORT_PREFIX to use less bytes.
// This doesn't change any method ids, just the prefixes.
const fn get_reveal_batch_proof_prefix() -> &'static [u8] {
    match option_env!("SHORT_PREFIX") {
        Some(_) => &[1],
        None => &[1, 1],
    }
}

const fn get_reveal_light_client_prefix() -> &'static [u8] {
    match option_env!("SHORT_PREFIX") {
        Some(_) => &[2],
        None => &[2, 2],
    }
}

/// Prefix for the reveal transaction ids - batch proof namespace.
pub const REVEAL_BATCH_PROOF_PREFIX: &[u8] = get_reveal_batch_proof_prefix();

/// Prefix for the reveal transaction ids - light client namespace.
pub const REVEAL_LIGHT_CLIENT_PREFIX: &[u8] = get_reveal_light_client_prefix();

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD: u64 = 300 * 1024;
pub const MAX_STATEDIFF_SIZE_PROOF_THRESHOLD: u64 = 400 * 1024;

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei
