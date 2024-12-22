use crypto_bigint::U256;

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
