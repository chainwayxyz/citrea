/// Prefix for the reveal transaction ids - batch proof namespace.
#[cfg(feature = "testing")]
pub const TO_BATCH_PROOF_PREFIX: &[u8] = &[1]; // since we changed the prefix to 1 genesis fork proving tests fail
#[cfg(not(feature = "testing"))]
pub const TO_BATCH_PROOF_PREFIX: &[u8] = &[1, 1];

/// Prefix for the reveal transaction ids - light client namespace.
#[cfg(feature = "testing")]
pub const TO_LIGHT_CLIENT_PREFIX: &[u8] = &[2];
#[cfg(not(feature = "testing"))]
pub const TO_LIGHT_CLIENT_PREFIX: &[u8] = &[2, 2];

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MIN_BASE_FEE_PER_GAS: u128 = 10_000_000; // 0.01 gwei

/// Maximum size of a bitcoin transaction body in bytes
#[cfg(feature = "testing")]
pub const MAX_TXBODY_SIZE: usize = 39700;
#[cfg(not(feature = "testing"))]
pub const MAX_TXBODY_SIZE: usize = 397000;

/// SHA-256 hash of "citrea" string
/// Used as the default tx merkle root when the block has no transactions
pub const EMPTY_TX_ROOT: [u8; 32] = [
    0xb9, 0x38, 0x83, 0x52, 0xdd, 0xd5, 0x9e, 0x59, 0xf6, 0x7a, 0x20, 0x8c, 0xbe, 0xba, 0xb3, 0xcd,
    0x6b, 0x23, 0xf9, 0x62, 0xa9, 0x03, 0x2e, 0xfe, 0x78, 0x58, 0xcd, 0x84, 0x01, 0x38, 0xaa, 0x27,
];
