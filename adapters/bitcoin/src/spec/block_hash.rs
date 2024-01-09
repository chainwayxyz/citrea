use std::fmt::Display;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHashTrait;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BlockHashWrapper(pub BlockHash);

impl BlockHashTrait for BlockHashWrapper {}

impl From<BlockHashWrapper> for [u8; 32] {
    fn from(val: BlockHashWrapper) -> Self {
        *val.0.as_ref()
    }
}

impl AsRef<[u8]> for BlockHashWrapper {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl BlockHashWrapper {
    pub fn to_byte_array(&self) -> [u8; 32] {
        self.0.as_raw_hash().to_byte_array()
    }
}

impl Display for BlockHashWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
