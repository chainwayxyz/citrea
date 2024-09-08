/// Prefix for the reveal transaction ids - batch proof namespace.
// pub const REVEAL_BATCH_PROOF_PREFIX: &[u8] = [1, 1].as_slice();
pub const REVEAL_BATCH_PROOF_PREFIX: &[u8] = [1].as_slice();

/// Prefix for the reveal transaction ids - light client namespace.
// pub const REVEAL_LIGHT_CLIENT_PREFIX: &[u8] = [2, 2].as_slice();
pub const REVEAL_LIGHT_CLIENT_PREFIX: &[u8] = [2].as_slice();

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD: u64 = 300 * 1024;
pub const MAX_STATEDIFF_SIZE_PROOF_THRESHOLD: u64 = 400 * 1024;

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei
