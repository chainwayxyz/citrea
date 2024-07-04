use bitcoin::block::Header;
use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
use bitcoin::BlockHash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;

use super::block_hash::BlockHashWrapper;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, BorshDeserialize, BorshSerialize, Serialize, Deserialize,
)]
pub struct HeaderWrapper {
    header: u8, // FIXME: Header, // not pub to prevent uses like block.header.header.merkle_root
    pub tx_count: u32,
    pub height: u64,
    txs_commitment: [u8; 32],
}

impl BlockHeaderTrait for HeaderWrapper {
    type Hash = BlockHashWrapper;

    fn prev_hash(&self) -> Self::Hash {
        unimplemented!()
        // FIXME: BlockHashWrapper(self.header.prev_blockhash)
    }

    fn hash(&self) -> Self::Hash {
        unimplemented!()
        // FIXME: BlockHashWrapper(self.header.block_hash())
    }

    fn txs_commitment(&self) -> Self::Hash {
        unimplemented!()
        // FIXME: BlockHashWrapper(BlockHash::from_raw_hash(self.txs_commitment.into()))
    }

    fn height(&self) -> u64 {
        self.height
    }

    fn time(&self) -> sov_rollup_interface::da::Time {
        Default::default()
        // FIXME: sov_rollup_interface::da::Time::from_secs(self.header.time as i64)
    }
}

impl HeaderWrapper {
    pub fn new(
        header: Header,
        tx_count: u32, // FIXME
        height: u64,
        txs_commitment: WitnessMerkleNode,
    ) -> Self {
        Self {
            header: Default::default(), // FIXME
            tx_count,
            height,
            txs_commitment: Default::default(), // FIXME
        }
    }

    pub fn block_hash(&self) -> BlockHash {
        unimplemented!()
        // FIXME: self.header.block_hash()
    }

    pub fn merkle_root(&self) -> TxMerkleNode {
        unimplemented!()
        // FIXME: self.header.merkle_root
    }

    pub fn header(&self) -> &Header {
        unimplemented!()
        // FIXME: &self.header
    }
}
