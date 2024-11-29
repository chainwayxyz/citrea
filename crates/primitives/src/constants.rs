#[cfg_attr(feature = "testing", allow(dead_code))]
const fn get_max_txbody_size() -> usize {
    #[cfg(feature = "testing")]
    {
        39700
    }
    #[cfg(not(feature = "testing"))]
    {
        397000
    }
}

/// Prefix for the reveal transaction ids - batch proof namespace.
pub const TO_BATCH_PROOF_PREFIX: &[u8] = &[1, 1];

/// Prefix for the reveal transaction ids - light client namespace.
pub const TO_LIGHT_CLIENT_PREFIX: &[u8] = &[2, 2];

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei

/// Maximum size of a bitcoin transaction body in bytes
pub const MAX_TXBODY_SIZE: usize = get_max_txbody_size();
