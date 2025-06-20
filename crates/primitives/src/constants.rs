/// Prefix for the reveal transaction ids.
#[cfg(feature = "testing")]
pub const REVEAL_TX_PREFIX: &[u8] = &[2]; // since we changed the prefix to 1 genesis fork proving tests fail
#[cfg(not(feature = "testing"))]
pub const REVEAL_TX_PREFIX: &[u8] = &[2, 2];

pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";

pub const MIN_BASE_FEE_PER_GAS: u64 = 10_000_000; // 0.01 gwei

/// Maximum size of a bitcoin transaction body in bytes
#[cfg(feature = "testing")]
pub const MAX_TX_BODY_SIZE: usize = 39700;
#[cfg(not(feature = "testing"))]
pub const MAX_TX_BODY_SIZE: usize = 397000;

#[cfg(feature = "testing")]
pub const MAX_WITNESS_CACHE_SIZE: usize = 6 * 1024 * 1024;
#[cfg(not(feature = "testing"))]
pub const MAX_WITNESS_CACHE_SIZE: usize = 512 * 1024 * 1024;

/// SHA-256 hash of "citrea" string
/// Used as the default tx merkle root when the block has no transactions
pub const EMPTY_TX_ROOT: [u8; 32] = [
    0xb9, 0x38, 0x83, 0x52, 0xdd, 0xd5, 0x9e, 0x59, 0xf6, 0x7a, 0x20, 0x8c, 0xbe, 0xba, 0xb3, 0xcd,
    0x6b, 0x23, 0xf9, 0x62, 0xa9, 0x03, 0x2e, 0xfe, 0x78, 0x58, 0xcd, 0x84, 0x01, 0x38, 0xaa, 0x27,
];

pub const PRE_TANGERINE_BRIDGE_INITIALIZE_PARAMS: &[u8] = &[
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 138, 199, 35,
    4, 137, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 45, 74, 32, 159, 179, 169, 97, 216, 177, 244, 236, 28, 170, 34, 12, 106, 80,
    184, 21, 254, 188, 11, 104, 157, 223, 11, 157, 223, 191, 153, 203, 116, 71, 158, 65, 172, 0,
    99, 6, 99, 105, 116, 114, 101, 97, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    10, 8, 0, 0, 0, 0, 59, 154, 202, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

/// Maximum size of a decompressed blob in bytes.
/// This is set to 1 MB for testing and 100 MB for production to allow larger blobs in real scenarios.
/// This limit is enforced during decompression to prevent excessive memory usage
/// and potential denial of service attacks like decompression bombs.
#[cfg(feature = "testing")]
pub const MAX_DECOMPRESSED_BLOB_SIZE: usize = 1024 * 1024; // 1 MB
#[cfg(not(feature = "testing"))]
pub const MAX_DECOMPRESSED_BLOB_SIZE: usize = 1024 * 1024 * 100; // 100 MB
