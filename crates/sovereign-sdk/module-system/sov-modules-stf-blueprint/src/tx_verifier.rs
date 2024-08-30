use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// RawTx represents a serialized rollup transaction received from the DA.
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct RawTx {
    /// Serialized transaction.
    pub data: Vec<u8>,
}
