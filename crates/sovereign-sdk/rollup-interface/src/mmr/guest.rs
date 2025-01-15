use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::{hash_pair, MMRChunk, MMRInclusionProof};

#[derive(
    Default, Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize,
)]
pub struct MMRGuest {
    pub subroots: Vec<[u8; 32]>,
    pub size: u32,
}

impl MMRGuest {
    pub fn new() -> Self {
        MMRGuest {
            subroots: Vec::new(),
            size: 0,
        }
    }

    pub fn append(&mut self, chunk: MMRChunk) {
        let mut current = chunk.hash();
        let mut size = self.size;

        while size % 2 == 1 {
            let sibling = self.subroots.pop().unwrap();
            current = hash_pair(sibling, current);
            size /= 2;
        }

        self.subroots.push(current);
        self.size += 1;
    }

    pub fn verify_proof(&self, chunk: &MMRChunk, mmr_proof: &MMRInclusionProof) -> bool {
        let mut current_hash = chunk.hash();

        for (i, sibling) in mmr_proof.inclusion_proof.iter().enumerate() {
            if mmr_proof.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, *sibling);
            } else {
                current_hash = hash_pair(*sibling, current_hash);
            }
        }

        if mmr_proof.subroot_idx >= self.subroots.len() as u32 {
            return false; // Subroot index is out of bounds
        }

        self.subroots[mmr_proof.subroot_idx as usize] == current_hash
    }
}
