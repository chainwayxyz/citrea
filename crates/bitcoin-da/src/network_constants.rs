use crypto_bigint::U256;
use sov_rollup_interface::da::LatestDaState;

pub const MAINNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
};
pub const TESTNET4_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
};
pub const SIGNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1E0377AE,
    max_target: U256::from_be_hex(
        "00000377AE000000000000000000000000000000000000000000000000000000",
    ),
};
pub const REGTEST_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x207FFFFF,
    max_target: U256::from_be_hex(
        "7FFFFF0000000000000000000000000000000000000000000000000000000000",
    ),
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConstants {
    /// Maximum bits of the chain
    pub max_bits: u32,
    /// Maximum target of the chain
    pub max_target: U256,
}

pub const INITIAL_MAINNET_STATE: LatestDaState = LatestDaState {
    block_hash: [0; 32],
    block_height: 0,
    total_work: [0; 32],
    current_target_bits: 0,
    epoch_start_time: 0,
    prev_11_timestamps: [0; 11],
};

pub const INITIAL_TESTNET4_STATE: LatestDaState = LatestDaState {
    block_hash: [
        51, 4, 48, 41, 24, 45, 99, 149, 148, 120, 189, 252, 198, 241, 9, 244, 115, 151, 164, 136,
        82, 175, 238, 140, 165, 244, 149, 155, 0, 0, 0, 0,
    ],
    block_height: 71608,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 188, 147, 68, 235,
        200, 221, 16, 251, 192,
    ],
    current_target_bits: 0x190455c3,
    epoch_start_time: 1739833936,
    prev_11_timestamps: [
        1740476135, 1740477336, 1740478537, 1740479738, 1740480939, 1740482140, 1740483341,
        1740484542, 1740485743, 1740486944, 1740474934,
    ],
};

pub const INITIAL_SIGNET_STATE: LatestDaState = LatestDaState {
    block_hash: [
        142, 4, 49, 254, 176, 6, 84, 77, 98, 18, 146, 26, 91, 26, 193, 182, 0, 13, 67, 34, 217,
        149, 195, 83, 233, 251, 105, 215, 0, 0, 0, 0,
    ],
    block_height: 23979,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 54, 47, 218,
        122, 35, 40,
    ],
    current_target_bits: 0x1d00e261,
    epoch_start_time: 1739362965,
    prev_11_timestamps: [
        1740479974, 1740480224, 1740482457, 1740483146, 1740483493, 1740483740, 1740483772,
        1740484206, 1740485210, 1740485655, 1740485821,
    ],
};

#[test]
fn verify_constants() {
    use crypto_bigint::Encoding;

    use crate::verifier::target_to_bits;

    assert_eq!(
        target_to_bits(&MAINNET_CONSTANTS.max_target.to_be_bytes()),
        MAINNET_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&TESTNET4_CONSTANTS.max_target.to_be_bytes()),
        TESTNET4_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&SIGNET_CONSTANTS.max_target.to_be_bytes()),
        SIGNET_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&REGTEST_CONSTANTS.max_target.to_be_bytes()),
        REGTEST_CONSTANTS.max_bits
    );
}
