//! Includes the types used by the citrea-evm.
use std::collections::BTreeMap;

use reth_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// BlockOverrides is a set of header fields to override.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockOverrides {
    /// Overrides the block number.
    ///
    /// For `eth_callMany` this will be the block number of the first simulated block. Each
    /// following block increments its block number by 1
    // Note: geth uses `number`, erigon uses `blockNumber`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "blockNumber"
    )]
    pub number: Option<u64>,
    /// Overrides the timestamp of the block.
    // Note: geth uses `time`, erigon uses `timestamp`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "timestamp",
        with = "alloy_serde::quantity::opt"
    )]
    pub time: Option<u64>,
    /// Overrides the gas limit of the block.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "alloy_serde::quantity::opt"
    )]
    pub gas_limit: Option<u64>,
    /// Overrides the coinbase address of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coinbase: Option<Address>,
    /// Overrides the prevrandao of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub random: Option<B256>,
    /// Overrides the basefee of the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<u64>,
    /// A dictionary that maps blockNumber to a user-defined hash. It could be queried from the
    /// solidity opcode BLOCKHASH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<BTreeMap<u64, B256>>,
}
