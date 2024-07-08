use bitcoin::block::Header as BitHeader;
use bitcoin::hash_types::WitnessMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;

use super::block_hash::BlockHashWrapper;

// HeaderWrapper is a wrapper around BlockHash to implement BlockHeaderTrait
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, BorshDeserialize, BorshSerialize, Serialize, Deserialize,
)]
pub struct HeaderWrapper {
    header: OurHeader, // not pub to prevent uses like block.header.header.merkle_root
    pub tx_count: u32,
    pub height: u64,
    txs_commitment: [u8; 32],
}

impl BlockHeaderTrait for HeaderWrapper {
    type Hash = BlockHashWrapper;

    fn prev_hash(&self) -> Self::Hash {
        BlockHashWrapper::from(self.header.prev_blockhash)
    }

    fn hash(&self) -> Self::Hash {
        let bit_header = BitHeader::from(&self.header);
        let block_hash = bit_header.block_hash();
        BlockHashWrapper::from(block_hash.to_byte_array())
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
        header: BitHeader,
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
        let bit_header = BitHeader::from(&self.header);
        bit_header.block_hash()
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        self.header.merkle_root
    }
}

#[derive(
    Copy,
    Debug,
    PartialEq,
    Eq,
    Clone,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct OurHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: [u8; 32],
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: [u8; 32],
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

#[derive(
    Copy,
    PartialEq,
    Eq,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct Version(i32);

#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
)]
pub struct CompactTarget(u32);

impl From<BitHeader> for OurHeader {
    fn from(value: BitHeader) -> Self {
        Self {
            version: Version(value.version.to_consensus()),
            prev_blockhash: value.prev_blockhash.to_byte_array(),
            merkle_root: value.merkle_root.to_byte_array(),
            time: value.time,
            bits: CompactTarget(value.bits.to_consensus()),
            nonce: value.nonce,
        }
    }
}

impl From<&OurHeader> for BitHeader {
    fn from(value: &OurHeader) -> Self {
        Self {
            version: bitcoin::block::Version::from_consensus(value.version.0),
            prev_blockhash: Hash::from_byte_array(value.prev_blockhash),
            merkle_root: Hash::from_byte_array(value.merkle_root),
            time: value.time,
            bits: bitcoin::CompactTarget::from_consensus(value.bits.0),
            nonce: value.nonce,
        }
    }
}
