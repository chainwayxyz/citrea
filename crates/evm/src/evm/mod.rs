use reth_primitives::{address, Address, BaseFeeParams, B256, KECCAK_EMPTY, U256};
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
#[cfg(feature = "native")]
pub(crate) mod error;

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

// Stores information about an EVM account
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub(crate) struct AccountInfo {
    pub(crate) balance: U256,
    pub(crate) code_hash: B256,
    pub(crate) nonce: u64,
}

impl Default for AccountInfo {
    fn default() -> Self {
        Self {
            balance: U256::default(),
            code_hash: KECCAK_EMPTY,
            nonce: 0,
        }
    }
}

/// Stores information about an EVM account and a corresponding account state.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub(crate) struct DbAccount {
    pub(crate) info: AccountInfo,
    pub(crate) storage: StateMap<U256, U256, BcsCodec>,
    pub(crate) keys: StateVec<U256, BcsCodec>,
}

impl DbAccount {
    fn new(parent_prefix: &Prefix, address: Address) -> Self {
        let prefix = Self::create_storage_prefix(parent_prefix, address);
        Self {
            info: Default::default(),
            storage: StateMap::with_codec(prefix.clone(), BcsCodec {}),
            keys: StateVec::with_codec(prefix, BcsCodec {}),
        }
    }

    pub(crate) fn new_with_info(
        parent_prefix: &Prefix,
        address: Address,
        info: AccountInfo,
    ) -> Self {
        let prefix = Self::create_storage_prefix(parent_prefix, address);
        Self {
            info,
            storage: StateMap::with_codec(prefix.clone(), BcsCodec {}),
            keys: StateVec::with_codec(prefix, BcsCodec {}),
        }
    }

    fn create_storage_prefix(parent_prefix: &Prefix, address: Address) -> Prefix {
        let mut prefix = parent_prefix.as_aligned_vec().clone().into_inner();
        prefix.extend_from_slice(address.as_ref());
        Prefix::new(prefix)
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
