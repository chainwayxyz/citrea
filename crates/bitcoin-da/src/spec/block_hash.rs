use std::fmt::Display;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHashTrait;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BlockHashWrapper(pub BlockHash);

impl BlockHashTrait for BlockHashWrapper {}

impl BorshSerialize for BlockHashWrapper {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_byte_array(), writer)
    }
}

impl BorshDeserialize for BlockHashWrapper {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let hash = BorshDeserialize::deserialize_reader(reader)?;
        Ok(BlockHashWrapper(BlockHash::from_byte_array(hash)))
    }
}

impl From<BlockHashWrapper> for [u8; 32] {
    fn from(val: BlockHashWrapper) -> Self {
        val.0.as_raw_hash().to_byte_array()
    }
}

impl From<[u8; 32]> for BlockHashWrapper {
    fn from(val: [u8; 32]) -> Self {
        BlockHashWrapper(BlockHash::from_byte_array(val))
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
