//! Shared builder types for the Bitcoin DA crate.

use core::fmt;

use bitcoin::{Transaction, Txid};
use serde::Serialize;

/// Both transaction and its hash.
#[derive(Clone, Serialize)]
pub struct TxWithId {
    /// ID (hash)
    pub id: Txid,
    /// Transaction
    pub tx: Transaction,
}

impl fmt::Debug for TxWithId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxWithId")
            .field("id", &self.id)
            .field("tx", &"...")
            .finish()
    }
}
