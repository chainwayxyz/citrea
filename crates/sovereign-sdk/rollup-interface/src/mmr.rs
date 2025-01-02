#![allow(missing_docs)]

use alloc::vec;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub trait NodeStore: Clone {
    fn save_node(&mut self, level: usize, index: usize, node: MMRNode) -> anyhow::Result<()>;
    fn load_node(&self, level: usize, index: usize) -> anyhow::Result<Option<MMRNode>>;
    fn get_tree_size(&self) -> usize;
    fn set_tree_size(&mut self, size: usize) -> anyhow::Result<()>;
}

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
pub struct MMRNative<S: NodeStore> {
    pub(crate) store: S,
    nodes: Vec<Vec<[u8; 32]>>,
    leaves: Vec<MMRNode>,
}

impl<S: NodeStore> MMRNative<S> {
    pub fn new(store: S) -> Self {
        let mut mmr = MMRNative {
            store: store.clone(),
            nodes: vec![vec![]],
            leaves: vec![],
        };

        // Initialize with existing leaves
        let current_size = store.get_tree_size();

        for i in 0..current_size {
            let Ok(Some(node)) = store.load_node(0, i) else {
                break;
            };
            let _ = mmr.append(node);
        }

        mmr
    }

    pub fn append(&mut self, node: MMRNode) -> anyhow::Result<()> {
        let hash = node.hash();
        self.nodes[0].push(hash);
        self.leaves.push(node.clone());

        let current_size = self.store.get_tree_size();
        self.store.save_node(0, current_size, node.clone())?;
        self.store.set_tree_size(current_size + 1)?;
        self.recalculate_peaks();
        Ok(())
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
        let index = self.leaves.iter().position(|node| node.wtxid == wtxid)? as u32;

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
        Some((self.leaves[index as usize].clone(), mmr_proof))
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

    #[derive(Clone)]
    struct InMemoryStore {
        storage: std::collections::HashMap<(usize, usize), MMRNode>,
        tree_size: usize,
    }

    impl InMemoryStore {
        fn new() -> Self {
            InMemoryStore {
                storage: std::collections::HashMap::new(),
                tree_size: 0,
            }
        }
    }

    impl NodeStore for InMemoryStore {
        fn save_node(&mut self, level: usize, index: usize, node: MMRNode) -> anyhow::Result<()> {
            self.storage.insert((level, index), node);
            Ok(())
        }

        fn load_node(&self, level: usize, index: usize) -> anyhow::Result<Option<MMRNode>> {
            Ok(self.storage.get(&(level, index)).cloned())
        }

        fn get_tree_size(&self) -> usize {
            self.tree_size
        }

        fn set_tree_size(&mut self, size: usize) -> anyhow::Result<()> {
            self.tree_size = size;
            Ok(())
        }
    }

    #[test]
    fn test_mmr_native() {
        let mut mmr = MMRNative::new(InMemoryStore::new());
        let mut nodes = vec![];

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);
            nodes.push(node.clone());

            mmr.append(node).unwrap();

            for j in 0..=i {
                let proof_node = nodes[j as usize].clone();
                let (node, mmr_proof) = mmr.generate_proof(proof_node.wtxid).unwrap();
                assert!(mmr.verify_proof(node.clone(), &mmr_proof));
            }
        }
    }

    #[test]
    fn test_native_proof_with_guest_verification() {
        let mut mmr_native = MMRNative::new(InMemoryStore::new());
        let mut mmr_guest = MMRGuest::new();

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);

            // Append to both Native and Guest
            mmr_native.append(node.clone()).unwrap();
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
        let mut mmr_native = MMRNative::new(InMemoryStore::new());
        let mut mmr_guest = MMRGuest::new();

        for i in 0..10 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);

            mmr_native.append(node.clone()).unwrap();
            mmr_guest.append(node.clone());
        }

        // Check subroots consistency
        let native_subroots = mmr_native.get_subroots();
        assert_eq!(native_subroots, mmr_guest.subroots);
    }

    #[test]
    fn test_large_dataset_verification() {
        let mut mmr_native = MMRNative::new(InMemoryStore::new());
        let mut mmr_guest = MMRGuest::new();
        let mut nodes = vec![];

        for i in 0..100 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 16];
            let node = MMRNode::new(wtxid, body);
            nodes.push(node.clone());

            mmr_native.append(node.clone()).unwrap();
            mmr_guest.append(node.clone());
        }

        for node in nodes {
            let (_, mmr_proof) = mmr_native.generate_proof(node.wtxid).unwrap();
            assert!(mmr_guest.verify_proof(&node, &mmr_proof));
        }
    }

    #[test]
    fn test_mmr_with_store() {
        let store = InMemoryStore::new();
        let mut mmr = MMRNative::new(store);

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);
            mmr.append(node).unwrap();
        }

        let mmr = MMRNative::new(mmr.store.clone());
        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRNode::new(wtxid, body);
            let (_, proof) = mmr.generate_proof(wtxid).unwrap();
            assert!(mmr.verify_proof(node, &proof));
        }
    }
}
