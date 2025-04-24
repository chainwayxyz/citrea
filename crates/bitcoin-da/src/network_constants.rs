use crypto_bigint::U256;
use sov_rollup_interface::da::LatestDaState;

pub const MAINNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
    // TODO: TBD before mainnet
    finality_depth: 8,
};
pub const TESTNET4_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
    finality_depth: 100,
};
pub const SIGNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1E0377AE,
    max_target: U256::from_be_hex(
        "00000377AE000000000000000000000000000000000000000000000000000000",
    ),
    finality_depth: 5,
};
pub const REGTEST_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x207FFFFF,
    max_target: U256::from_be_hex(
        "7FFFFF0000000000000000000000000000000000000000000000000000000000",
    ),
    finality_depth: 5,
};

pub fn get_network_constants(network: &bitcoin::Network) -> NetworkConstants {
    match network {
        bitcoin::Network::Bitcoin => MAINNET_CONSTANTS,
        bitcoin::Network::Testnet | bitcoin::Network::Testnet4 => TESTNET4_CONSTANTS,
        bitcoin::Network::Signet => SIGNET_CONSTANTS,
        bitcoin::Network::Regtest => REGTEST_CONSTANTS,
        _ => unreachable!("Unsupport network"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConstants {
    /// Maximum bits of the chain
    pub max_bits: u32,
    /// Maximum target of the chain
    pub max_target: U256,
    /// Network finality depth
    pub finality_depth: u64,
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
        177, 30, 245, 240, 148, 228, 201, 10, 169, 117, 171, 23, 153, 213, 126, 0, 82, 34, 206,
        105, 206, 59, 65, 158, 204, 24, 203, 208, 0, 0, 0, 0,
    ],
    block_height: 74246,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 242, 121, 228, 216,
        103, 138, 95, 229, 162,
    ],
    current_target_bits: 0x190461c8,
    epoch_start_time: 1741056039,
    prev_11_timestamps: [
        1742436071, 1742437272, 1742438473, 1742439674, 1742440875, 1742442076, 1742441609,
        1742442810, 1742432468, 1742433669, 1742434870,
    ],
};

pub const INITIAL_SIGNET_STATE: LatestDaState = LatestDaState {
    block_hash: [
        245, 79, 209, 136, 168, 232, 39, 32, 63, 156, 16, 98, 53, 39, 221, 58, 154, 156, 163, 63,
        207, 76, 63, 27, 100, 126, 53, 190, 9, 3, 0, 0,
    ],
    block_height: 12,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 191,
        197, 4,
    ],
    current_target_bits: 0x1e0377ae,
    epoch_start_time: 1598918400,
    prev_11_timestamps: [
        1732838717, 1732838728, 1732838622, 1732838632, 1732838643, 1732838653, 1732838665,
        1732838675, 1732838686, 1732838696, 1732838707,
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
