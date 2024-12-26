#![allow(missing_docs)]
use alloc::vec;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: usize,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<[u8; 32]>,
}

impl MMRInclusionProof {
    pub fn new(subroot_idx: usize, internal_idx: u32, inclusion_proof: Vec<[u8; 32]>) -> Self {
        MMRInclusionProof {
            subroot_idx,
            internal_idx,
            inclusion_proof,
        }
    }

    pub fn get_subroot(&self, leaf: [u8; 32]) -> [u8; 32] {
        let mut current_hash = leaf;
        for i in 0..self.inclusion_proof.len() {
            let sibling = self.inclusion_proof[i];
            if self.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, current_hash);
            }
        }
        current_hash
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRNode {
    pub wtxid: [u8; 32],
    pub body: Vec<u8>,
}

impl MMRNode {
    pub fn new(wtxid: [u8; 32], body: Vec<u8>) -> Self {
        MMRNode { wtxid, body }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(self.wtxid);
        hasher.update(&self.body);
        hasher.finalize().into()
    }
}

#[derive(
    Default, Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize,
)]
pub struct MMRNative {
    pub nodes: Vec<Vec<[u8; 32]>>,
    pub leaf_nodes: Vec<MMRNode>,
}

impl MMRNative {
    pub fn new() -> Self {
        MMRNative {
            nodes: vec![vec![]],
            leaf_nodes: vec![],
        }
    }

    pub fn append(&mut self, node: MMRNode) {
        let hash = node.hash();
        self.leaf_nodes.push(node);
        self.nodes[0].push(hash);
        self.recalculate_peaks();
    }

    fn recalculate_peaks(&mut self) {
        let depth = self.nodes.len();
        for level in 0..depth - 1 {
            if self.nodes[level].len() % 2 == 1 {
                break;
            } else {
                let node = hash_pair(
                    self.nodes[level][self.nodes[level].len() - 2],
                    self.nodes[level][self.nodes[level].len() - 1],
                );
                self.nodes[level + 1].push(node);
            }
        }
        if self.nodes[depth - 1].len() > 1 {
            let node = hash_pair(self.nodes[depth - 1][0], self.nodes[depth - 1][1]);
            self.nodes.push(vec![node]);
        }
    }

    fn get_subroots(&self) -> Vec<[u8; 32]> {
        let mut subroots: Vec<[u8; 32]> = vec![];
        for level in &self.nodes {
            if level.len() % 2 == 1 {
                subroots.push(level[level.len() - 1]);
            }
        }
        subroots.reverse();
        subroots
    }

    pub fn generate_proof(&self, wtxid: [u8; 32]) -> Option<(MMRNode, MMRInclusionProof)> {
        let index = self
            .leaf_nodes
            .iter()
            .position(|node| node.wtxid == wtxid)? as u32;

        let mut proof: Vec<[u8; 32]> = vec![];
        let mut current_index = index;
        let mut current_level = 0;

        while !(current_index == self.nodes[current_level].len() as u32 - 1
            && self.nodes[current_level].len() % 2 == 1)
        {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            proof.push(self.nodes[current_level][sibling_index as usize]);
            current_index /= 2;
            current_level += 1;
        }

        let (subroot_idx, internal_idx) = self.get_helpers_from_index(index);
        let mmr_proof = MMRInclusionProof::new(subroot_idx, internal_idx, proof);
        Some((self.leaf_nodes[index as usize].clone(), mmr_proof))
    }

    fn get_helpers_from_index(&self, index: u32) -> (usize, u32) {
        let xor = (self.nodes[0].len() as u32) ^ index;
        let xor_leading_digit = 31 - xor.leading_zeros() as usize;
        let internal_idx = index & ((1 << xor_leading_digit) - 1);
        let leading_zeros_size = 31 - (self.nodes[0].len() as u32).leading_zeros() as usize;
        let mut subtree_idx = 0;
        for i in xor_leading_digit + 1..=leading_zeros_size {
            if self.nodes[0].len() & (1 << i) != 0 {
                subtree_idx += 1;
            }
        }
        (subtree_idx, internal_idx)
    }

    pub fn verify_proof(&self, node: MMRNode, mmr_proof: &MMRInclusionProof) -> bool {
        let subroot = mmr_proof.get_subroot(node.hash());
        let subroots = self.get_subroots();
        subroots[mmr_proof.subroot_idx] == subroot
    }
}

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
            subroots: vec![],
            size: 0,
        }
    }

    pub fn append(&mut self, node: MMRNode) {
        let mut current = node.hash();
        let mut size = self.size;
        while size % 2 == 1 {
            let sibling = self.subroots.pop().unwrap();
            current = hash_pair(sibling, current);
            size /= 2
        }
        self.subroots.push(current);
        self.size += 1;
    }

    pub fn verify_proof(&self, node: &MMRNode, mmr_proof: &MMRInclusionProof) -> bool {
        let mut current_hash = node.hash();
        for (i, sibling) in mmr_proof.inclusion_proof.iter().enumerate() {
            if mmr_proof.internal_idx & (1 << i) == 0 {
                current_hash = hash_pair(current_hash, *sibling);
            } else {
                current_hash = hash_pair(*sibling, current_hash);
            }
        }
        if mmr_proof.subroot_idx >= self.subroots.len() {
            return false; // Subroot index is out of bounds, verification fails
        }
        self.subroots[mmr_proof.subroot_idx] == current_hash
    }
}

pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmr_native() {
        let mut mmr = MMRNative::new();
        let mut nodes = vec![];

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);
            nodes.push(node.clone());

            mmr.append(node);

            for j in 0..=i {
                let proof_node = nodes[j as usize].clone();
                let (node, mmr_proof) = mmr.generate_proof(proof_node.wtxid).unwrap();
                assert!(mmr.verify_proof(node.clone(), &mmr_proof));
            }
        }
    }

    #[test]
    fn test_native_proof_with_guest_verification() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);

            // Append to both Native and Guest
            mmr_native.append(node.clone());
            mmr_guest.append(node.clone());

            // Generate proof in Native and verify in Guest
            for j in 0..=i {
                let proof_node = MMRNode::new([j as u8; 32], vec![j as u8; 8]);
                let (_, mmr_proof) = mmr_native.generate_proof(proof_node.wtxid).unwrap();

                // Verify proof using Guest
                assert!(mmr_guest.verify_proof(&proof_node, &mmr_proof));
            }
        }
    }

    #[test]
    fn test_consistency_between_native_and_guest() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();

        for i in 0..10 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);

            mmr_native.append(node.clone());
            mmr_guest.append(node.clone());
        }

        // Check subroots consistency
        let native_subroots = mmr_native.get_subroots();
        assert_eq!(native_subroots, mmr_guest.subroots);
    }

    #[test]
    fn test_large_dataset_verification() {
        let mut mmr_native = MMRNative::new();
        let mut mmr_guest = MMRGuest::new();
        let mut nodes = vec![];

        for i in 0..100 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 16];
            let node = MMRNode::new(wtxid, body);
            nodes.push(node.clone());

            mmr_native.append(node.clone());
            mmr_guest.append(node.clone());
        }

        for node in nodes {
            let (_, mmr_proof) = mmr_native.generate_proof(node.wtxid).unwrap();
            assert!(mmr_guest.verify_proof(&node, &mmr_proof));
        }
    }
}
