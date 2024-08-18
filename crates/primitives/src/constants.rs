pub const ROLLUP_NAME: &str = "citrea-devnet";

/// Leading zeros prefix for the reveal transaction id.
pub const DA_TX_ID_LEADING_ZEROS: &[u8] = [0, 0].as_slice();

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD: u64 = 300 * 1024;
pub const MAX_STATEDIFF_SIZE_PROOF_THRESHOLD: u64 = 400 * 1024;

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei
