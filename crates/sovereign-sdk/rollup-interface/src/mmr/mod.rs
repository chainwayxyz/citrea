#![allow(missing_docs)]
use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod guest;
#[cfg(any(test, feature = "native", feature = "testing"))]
mod native;
#[cfg(any(test, feature = "native", feature = "testing"))]
mod test_utils;
#[cfg(test)]
mod tests;

pub use guest::*;
#[cfg(any(feature = "native", feature = "testing"))]
pub use native::*;
#[cfg(any(feature = "native", feature = "testing"))]
pub use test_utils::*;

pub type MMRNodeHash = [u8; 32];
pub type Wtxid = [u8; 32];

pub trait NodeStore {
    fn save_node(&mut self, level: u32, index: u32, hash: MMRNodeHash) -> Result<()>;
    fn load_node(&self, level: u32, index: u32) -> Result<Option<MMRNodeHash>>;
    fn save_chunk(&mut self, hash: MMRNodeHash, chunk: MMRChunk) -> Result<()>;
    fn load_chunk(&self, hash: MMRNodeHash) -> Result<Option<MMRChunk>>;
    fn get_tree_size(&self) -> u32;
    fn set_tree_size(&mut self, size: u32) -> Result<()>;
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: u32,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<MMRNodeHash>,
}

impl MMRInclusionProof {
    pub fn new(subroot_idx: u32, internal_idx: u32, inclusion_proof: Vec<MMRNodeHash>) -> Self {
        MMRInclusionProof {
            subroot_idx,
            internal_idx,
            inclusion_proof,
        }
    }

    pub fn get_subroot(&self, leaf: MMRNodeHash) -> MMRNodeHash {
        let mut current_hash = leaf;
        for (i, sibling) in self.inclusion_proof.iter().enumerate() {
            if self.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, *sibling);
            } else {
                current_hash = hash_pair(*sibling, current_hash);
            }
        }
        current_hash
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRChunk {
    pub wtxid: Wtxid,
    pub body: Vec<u8>,
}

impl MMRChunk {
    pub fn new(wtxid: Wtxid, body: Vec<u8>) -> Self {
        MMRChunk { wtxid, body }
    }

    pub fn hash(&self) -> MMRNodeHash {
        let mut hasher = Sha256::default();
        hasher.update(self.wtxid);
        hasher.update(&self.body);
        hasher.finalize().into()
    }
}

pub fn hash_pair(left: MMRNodeHash, right: MMRNodeHash) -> MMRNodeHash {
    let mut hasher = Sha256::default();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
