use alloy_eips::eip1559::BaseFeeParams;
use alloy_primitives::{address, Address, B256, U256};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_state::storage::StateValueCodec;

pub(crate) mod conversions;
pub(crate) mod db;
mod db_commit;
pub(crate) mod db_init;
pub(crate) mod executor;
pub(crate) mod handler;
pub(crate) mod primitive_types;
/// System contracts used for system transactions
pub mod system_contracts;
/// System events used for creating system transactions
pub mod system_events;
/// Get the last l1 block hash set in bitcoin light client contract
pub use executor::{
    get_last_l1_height_and_hash_in_light_client, get_last_l1_height_in_light_client,
};

#[cfg(feature = "native")]
pub(crate) mod call;

#[cfg(all(test, feature = "native"))]
mod tests;

pub use primitive_types::RlpEvmTransaction;
use sov_state::codec::BorshCodec;

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

/// Stores information about an EVM account
#[derive(Default, Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct AccountInfo {
    /// Balance
    pub balance: U256,
    /// Nonce
    pub nonce: u64,
    /// Code hash
    pub code_hash: Option<B256>,
}

impl BorshSerialize for AccountInfo {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let balance = self.balance.as_limbs();
        let nonce = self.nonce;
        let code_hash = self.code_hash.as_ref().map(|v| &v.0);
        BorshSerialize::serialize(balance, writer)?;
        BorshSerialize::serialize(&nonce, writer)?;
        BorshSerialize::serialize(&code_hash, writer)
    }
}

impl BorshDeserialize for AccountInfo {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let balance: [u64; 4] = BorshDeserialize::deserialize_reader(reader)?;
        let nonce = BorshDeserialize::deserialize_reader(reader)?;
        let code_hash: Option<[u8; 32]> = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self {
            balance: U256::from_limbs(balance),
            nonce,
            code_hash: code_hash.map(|v| B256::from_slice(&v)),
        })
    }
}

impl StateValueCodec<AccountInfo> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &AccountInfo) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8 + 32 + 1);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<AccountInfo, Self::Error> {
        borsh::from_slice(bytes)
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
            coinbase: Address::ZERO,
            block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
            base_fee_params: BaseFeeParams::ethereum(),
        }
    }
}
