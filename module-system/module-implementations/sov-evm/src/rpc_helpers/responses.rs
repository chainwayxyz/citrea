use std::hash::Hash;

use alloy_primitives::Bytes;
use reth_primitives::{Address, U256};
use revm::primitives::B256;

/// Ethereum Log emitted by a transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogResponse {
    /// Address
    pub address: Address,
    /// All topics of the log
    pub topics: Vec<B256>,
    /// Additional data fields of the log
    pub data: Bytes,
    /// Hash of the block the transaction that emitted this log was mined in
    pub block_hash: Option<B256>,
    /// Number of the block the transaction that emitted this log was mined in
    pub block_number: Option<U256>,
    /// Transaction Hash
    pub transaction_hash: Option<B256>,
    /// Index of the Transaction in the block
    pub transaction_index: Option<U256>,
    /// Log Index in Block
    pub log_index: Option<U256>,
    /// Geth Compatibility Field: whether this log was removed
    #[serde(default)]
    pub removed: bool,
}
