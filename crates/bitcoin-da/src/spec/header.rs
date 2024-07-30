use core::ops::Deref;

use bitcoin::block::{Header as BitcoinHeader, Version};
use bitcoin::hash_types::WitnessMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;

use super::block_hash::BlockHashWrapper;

// HeaderWrapper is a wrapper around BlockHash to implement BlockHeaderTrait
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, BorshDeserialize, BorshSerialize, Serialize, Deserialize,
)]
pub struct HeaderWrapper {
    header: BitcoinHeaderWrapper, // not pub to prevent uses like block.header.header.merkle_root
    pub tx_count: u32,
    pub height: u64,
    txs_commitment: [u8; 32],
}

impl BlockHeaderTrait for HeaderWrapper {
    type Hash = BlockHashWrapper;

    fn prev_hash(&self) -> Self::Hash {
        BlockHashWrapper::from(self.header.prev_blockhash.to_byte_array())
    }

    fn hash(&self) -> Self::Hash {
        BlockHashWrapper::from(self.header.block_hash().to_byte_array())
    }

    fn txs_commitment(&self) -> Self::Hash {
        BlockHashWrapper::from(self.txs_commitment)
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn time(&self) -> sov_rollup_interface::da::Time {
        sov_rollup_interface::da::Time::from_secs(self.header.time as i64)
    }
}

impl HeaderWrapper {
    pub fn new(
        header: BitcoinHeader,
        tx_count: u32,
        height: u64,
        txs_commitment: WitnessMerkleNode,
    ) -> Self {
        Self {
            header: header.into(),
            tx_count,
            height,
            txs_commitment: txs_commitment.to_byte_array(),
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        self.header.merkle_root.to_byte_array()
    }
}

/// BitcoinHeaderWrapper is a wrapper around BitcoinHeaderWrapper to implement borsh serde
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct BitcoinHeaderWrapper {
    header: BitcoinHeader,
}

impl BorshSerialize for BitcoinHeaderWrapper {
    #[inline]
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.header.version.to_consensus(), writer)?;
        BorshSerialize::serialize(&self.header.prev_blockhash.to_byte_array(), writer)?;
        BorshSerialize::serialize(&self.header.merkle_root.to_byte_array(), writer)?;
        BorshSerialize::serialize(&self.header.time, writer)?;
        BorshSerialize::serialize(&self.header.bits.to_consensus(), writer)?;
        BorshSerialize::serialize(&self.header.nonce, writer)
    }
}

impl BorshDeserialize for BitcoinHeaderWrapper {
    #[inline]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let version = i32::deserialize_reader(reader)?;
        let prev_blockhash = <[u8; 32]>::deserialize_reader(reader)?;
        let merkle_root = <[u8; 32]>::deserialize_reader(reader)?;
        let time = u32::deserialize_reader(reader)?;
        let bits = u32::deserialize_reader(reader)?;
        let nonce = u32::deserialize_reader(reader)?;

        let header = BitcoinHeader {
            version: Version::from_consensus(version),
            prev_blockhash: BlockHash::from_byte_array(prev_blockhash),
            merkle_root: TxMerkleNode::from_byte_array(merkle_root),
            time,
            bits: CompactTarget::from_consensus(bits),
            nonce,
        };

        Ok(Self { header })
    }
}

impl Deref for BitcoinHeaderWrapper {
    type Target = BitcoinHeader;
    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl From<BitcoinHeader> for BitcoinHeaderWrapper {
    fn from(header: BitcoinHeader) -> Self {
        Self { header }
    }
}
