use std::fmt::Display;
use std::io::prelude::{Read, Write};

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHashTrait;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct BlockHashWrapper(pub BlockHash);

impl BorshDeserialize for BlockHashWrapper {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = BorshDeserialize::deserialize_reader(reader)?;
        Ok(Self(BlockHash::from_byte_array(bytes)))
    }
}

impl BorshSerialize for BlockHashWrapper {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(self.0.as_byte_array(), writer)
    }
}

impl BlockHashTrait for BlockHashWrapper {}

impl From<BlockHashWrapper> for [u8; 32] {
    fn from(val: BlockHashWrapper) -> Self {
        val.0.as_raw_hash().to_byte_array()
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
