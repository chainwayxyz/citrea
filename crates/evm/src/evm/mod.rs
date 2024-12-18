use alloy_eips::eip1559::BaseFeeParams;
use alloy_primitives::{address, Address, B256, U256};
use revm::primitives::bitvec::view::BitViewSized;
use revm::primitives::specification::SpecId;
use serde::{Deserialize, Serialize};
use sov_modules_api::{StateMap, StateVec};
use sov_state::Prefix;

pub(crate) mod conversions;
pub(crate) mod db;
mod db_commit;
pub(crate) mod db_init;
pub(crate) mod executor;
pub(crate) mod handler;
pub(crate) mod primitive_types;
/// System contracts used for system transactions
pub mod system_contracts;
pub(crate) mod system_events;

#[cfg(feature = "native")]
pub(crate) mod call;

#[cfg(all(test, feature = "native"))]
mod tests;

pub use primitive_types::RlpEvmTransaction;
use sov_state::codec::BcsCodec;

#[cfg(all(test, feature = "native"))]
use crate::tests::DEFAULT_CHAIN_ID;

/// Bitcoin light client contract address
pub const BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS: Address =
    address!("3100000000000000000000000000000000000001");
/// Bridge contract address
pub const BRIDGE_CONTRACT_ADDRESS: Address = address!("3100000000000000000000000000000000000002");
/// Base fee vault address
pub const BASE_FEE_VAULT: Address = address!("3100000000000000000000000000000000000003");
/// L1 fee vault address
pub const L1_FEE_VAULT: Address = address!("3100000000000000000000000000000000000004");
/// Priority fee vault address
pub const PRIORITY_FEE_VAULT: Address = address!("3100000000000000000000000000000000000005");

/// Prefix for Storage module for evm::Account::storage
pub const DBACCOUNT_STORAGE_PREFIX: [u8; 6] = *b"Evm/s/";
/// Prefix for Storage module for evm::Account::keys
pub const DBACCOUNT_KEYS_PREFIX: [u8; 6] = *b"Evm/k/";

// Stores information about an EVM account
#[derive(Default, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub(crate) struct AccountInfo {
    pub(crate) balance: U256,
    pub(crate) nonce: u64,
    pub(crate) code_hash: Option<B256>,
}

/// Stores information about an EVM account and a corresponding account state.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub(crate) struct DbAccount {
    pub(crate) storage: StateMap<U256, U256, BcsCodec>,
    pub(crate) keys: StateVec<U256, BcsCodec>,
}

impl DbAccount {
    pub fn new(address: Address) -> Self {
        Self {
            storage: StateMap::with_codec(Self::create_storage_prefix(address), BcsCodec {}),
            keys: StateVec::with_codec(Self::create_keys_prefix(address), BcsCodec {}),
        }
    }

    fn create_storage_prefix(address: Address) -> Prefix {
        let mut prefix = [0u8; 26];
        prefix[0..6].copy_from_slice(&DBACCOUNT_STORAGE_PREFIX);
        prefix[6..].copy_from_slice(address.as_raw_slice());
        Prefix::new(prefix.to_vec())
    }

    fn create_keys_prefix(address: Address) -> Prefix {
        let mut prefix = [0u8; 26];
        prefix[0..6].copy_from_slice(&DBACCOUNT_KEYS_PREFIX);
        prefix[6..].copy_from_slice(address.as_raw_slice());
        Prefix::new(prefix.to_vec())
    }
}

/// EVM Chain configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EvmChainConfig {
    /// Unique chain id
    /// Chains can be registered at <https://github.com/ethereum-lists/chains>.
    pub chain_id: u64,

    /// Limits size of contract code size
    /// By default it is 0x6000 (~25kb).
    pub limit_contract_code_size: Option<usize>,

    /// DO NOT USE THIS FIELD ever again
    ///
    /// List of EVM hardforks by block number
    pub spec: Vec<(u64, SpecId)>,

    /// Coinbase where all the fees go
    pub coinbase: Address,

    /// Gas limit for single block
    pub block_gas_limit: u64,

    /// Base fee params.
    pub base_fee_params: BaseFeeParams,
}

#[cfg(all(test, feature = "native"))]
impl Default for EvmChainConfig {
    fn default() -> EvmChainConfig {
        EvmChainConfig {
            chain_id: DEFAULT_CHAIN_ID,
            limit_contract_code_size: None,
            spec: vec![(0, SpecId::SHANGHAI)],
            coinbase: Address::ZERO,
            block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
            base_fee_params: BaseFeeParams::ethereum(),
        }
    }
}
