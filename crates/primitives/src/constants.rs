/// Prefix for the reveal transaction ids - batch proof namespace.
#[cfg(feature = "short-prefix")]
pub const TO_BATCH_PROOF_PREFIX: &[u8] = &[1];
#[cfg(not(feature = "short-prefix"))]
pub const TO_BATCH_PROOF_PREFIX: &[u8] = &[1, 1];

/// Prefix for the reveal transaction ids - light client namespace.
#[cfg(feature = "short-prefix")]
pub const TO_LIGHT_CLIENT_PREFIX: &[u8] = &[2];
#[cfg(not(feature = "short-prefix"))]
pub const TO_LIGHT_CLIENT_PREFIX: &[u8] = &[2, 2];

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei

/// Maximum size of a bitcoin transaction body in bytes
#[cfg(feature = "testing")]
pub const MAX_TXBODY_SIZE: usize = 39700;
#[cfg(not(feature = "testing"))]
pub const MAX_TXBODY_SIZE: usize = 397000;
