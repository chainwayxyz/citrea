use crypto_bigint::U256;
use sov_rollup_interface::Network;

const MAINNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
    network: BitcoinNetwork::Mainnet,
};
const TESTNET4_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
    network: BitcoinNetwork::Testnet4,
};
const SIGNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1E0377AE,
    max_target: U256::from_be_hex(
        "00000377AE000000000000000000000000000000000000000000000000000000",
    ),
    network: BitcoinNetwork::Signet,
};
const REGTEST_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x207FFFFF,
    max_target: U256::from_be_hex(
        "7FFFFF0000000000000000000000000000000000000000000000000000000000",
    ),
    network: BitcoinNetwork::Regtest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet4,
    Signet,
    Regtest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConstants {
    /// Maximum bits of the chain
    pub max_bits: u32,
    /// Maximum target of the chain
    pub max_target: U256,
    /// Type of the bitcoin network
    pub network: BitcoinNetwork,
}

impl From<Network> for NetworkConstants {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => MAINNET_CONSTANTS,
            Network::Testnet => TESTNET4_CONSTANTS,
            Network::Devnet => SIGNET_CONSTANTS,
            Network::Nightly => REGTEST_CONSTANTS,
        }
    }
}
