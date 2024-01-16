use reth_primitives::B256;
use serde::{Deserialize, Serialize};

/// Parameters for `eth_getTransactionByHash` RPC method.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct GetTransactionByHashParams {
    /// Hash of the transaction to get.
    pub hash: B256,
    /// Whether to look for the tx in the mempool only in sequencer or not.
    pub mempool_only: Option<bool>,
}
