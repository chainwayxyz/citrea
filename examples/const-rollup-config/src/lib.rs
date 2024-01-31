pub const ROLLUP_NAME: &str = "chainway";
pub const TEST_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121213";

pub const SEQUENCER_DA_ADDRESS: [u8; 33] = [
    2, 88, 141, 32, 42, 252, 193, 238, 74, 181, 37, 76, 120, 71, 236, 37, 185, 161, 53, 187, 218,
    15, 43, 198, 158, 225, 167, 20, 116, 159, 215, 125, 201,
];

/// The namespace used by the rollup to store its data. This is a raw slice of 8 bytes.
/// The rollup stores its data in the namespace b"sov-test" on Celestia. Which in this case is encoded using the
/// ascii representation of each character.
pub const ROLLUP_BATCH_NAMESPACE_RAW: [u8; 10] = [0, 0, 115, 111, 118, 45, 116, 101, 115, 116];

/// The namespace used by the rollup to store aggregated ZK proofs.
pub const ROLLUP_PROOF_NAMESPACE_RAW: [u8; 10] = [115, 111, 118, 45, 116, 101, 115, 116, 45, 112];

/// Leading zeros prefix for the reveal transaction id.
pub const DA_TX_ID_LEADING_ZEROS: &[u8] = [0, 0].as_slice();
