#![allow(missing_docs)]

use alloc::vec;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type MMRNodeHash = [u8; 32];
pub type Wtxid = [u8; 32];

pub trait NodeStore {
    fn save_node(&mut self, level: usize, index: usize, hash: MMRNodeHash) -> Result<()>;
    fn load_node(&self, level: usize, index: usize) -> Result<Option<MMRNodeHash>>;
    fn save_chunk(&mut self, wtxid: Wtxid, chunk: MMRChunk) -> Result<()>;
    fn load_chunk(&self, wtxid: Wtxid) -> Result<Option<MMRChunk>>;
    fn get_tree_size(&self) -> usize;
    fn set_tree_size(&mut self, size: usize) -> Result<()>;
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct MMRInclusionProof {
    pub subroot_idx: usize,
    pub internal_idx: u32,
    pub inclusion_proof: Vec<MMRNodeHash>,
}

impl MMRInclusionProof {
    pub fn new(subroot_idx: usize, internal_idx: u32, inclusion_proof: Vec<MMRNodeHash>) -> Self {
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

#[derive(
    Default, Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize,
)]
pub struct MMRNative<S: NodeStore> {
    pub store: S,
    pub cache: BTreeMap<(usize, usize), MMRNodeHash>,
}

impl<S: NodeStore> MMRNative<S> {
    pub fn new(store: S) -> Self {
        let mut mmr = MMRNative {
            store,
            cache: BTreeMap::new(),
        };
        mmr.recalculate_peaks().unwrap();
        mmr
    }

    pub fn append(&mut self, chunk: MMRChunk) -> Result<()> {
        let hash = chunk.hash();
        self.store.save_chunk(chunk.wtxid, chunk)?;
        let current_size = self.store.get_tree_size();
        self.store.save_node(0, current_size, hash)?;
        self.cache.insert((0, current_size), hash);
        self.store.set_tree_size(current_size + 1)?;
        self.recalculate_peaks()?;
        Ok(())
    }

    fn recalculate_peaks(&mut self) -> Result<()> {
        let mut size = self.store.get_tree_size();
        let mut level = 0;

        while size > 1 {
            if size % 2 == 0 {
                let left = self.load_node(level, size - 2)?.unwrap();
                let right = self.load_node(level, size - 1)?.unwrap();
                let parent = hash_pair(left, right);

                self.store.save_node(level + 1, size / 2 - 1, parent)?;
                self.cache.insert((level + 1, size / 2 - 1), parent);
            }
            size /= 2;
            level += 1;
        }
        Ok(())
    }

    pub fn generate_proof(
        &mut self,
        wtxid: Wtxid,
    ) -> Result<Option<(MMRChunk, MMRInclusionProof)>> {
        let chunk = self
            .store
            .load_chunk(wtxid)?
            .ok_or_else(|| anyhow::anyhow!("Chunk not found"))?;
        let index = self
            .find_chunk_index(chunk.hash())?
            .ok_or_else(|| anyhow::anyhow!("Chunk index not found"))?;

        let mut proof: Vec<MMRNodeHash> = vec![];
        let mut current_index = index;
        let mut current_level = 0;

        while current_index % 2 == 1 || self.load_node(current_level, current_index + 1)?.is_some()
        {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            proof.push(self.load_node(current_level, sibling_index)?.unwrap());
            current_index /= 2;
            current_level += 1;
        }

        let (subroot_idx, internal_idx) = self.get_helpers_from_index(index as u32);
        let mmr_proof = MMRInclusionProof::new(subroot_idx, internal_idx, proof);
        Ok(Some((chunk, mmr_proof)))
    }

    fn load_node(&mut self, level: usize, index: usize) -> Result<Option<MMRNodeHash>> {
        if let Some(&hash) = self.cache.get(&(level, index)) {
            Ok(Some(hash))
        } else {
            let Some(node) = self.store.load_node(level, index)? else {
                return Ok(None);
            };

            self.cache.insert((level, index), node);

            Ok(Some(node))
        }
    }

    fn find_chunk_index(&mut self, hash: MMRNodeHash) -> Result<Option<usize>> {
        let size = self.store.get_tree_size();
        for i in 0..size {
            if let Some(node_hash) = self.load_node(0, i)? {
                if node_hash == hash {
                    return Ok(Some(i));
                }
            }
        }
        Ok(None)
    }

    fn get_helpers_from_index(&self, index: u32) -> (usize, u32) {
        let xor = (self.store.get_tree_size() as u32) ^ index;
        let xor_leading_digit = 31 - xor.leading_zeros() as usize;
        let internal_idx = index & ((1 << xor_leading_digit) - 1);
        let leading_zeros_size = 31 - (self.store.get_tree_size() as u32).leading_zeros() as usize;
        let mut subtree_idx = 0;
        for i in xor_leading_digit + 1..=leading_zeros_size {
            if self.store.get_tree_size() & (1 << i) != 0 {
                subtree_idx += 1;
            }
        }
        (subtree_idx, internal_idx)
    }

    pub fn verify_proof(&mut self, chunk: MMRChunk, mmr_proof: &MMRInclusionProof) -> bool {
        let subroot = mmr_proof.get_subroot(chunk.hash());
        let subroots = self.get_subroots();
        subroots[mmr_proof.subroot_idx] == subroot
    }

    fn get_subroots(&mut self) -> Vec<MMRNodeHash> {
        let mut subroots: Vec<MMRNodeHash> = vec![];
        let mut size = self.store.get_tree_size();
        let mut level = 0;

        while size > 0 {
            if size % 2 == 1 {
                let subroot = self.load_node(level, size - 1).ok().flatten().unwrap();
                subroots.push(subroot);
            }
            size /= 2;
            level += 1;
        }
        subroots.reverse();
        subroots
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

        if mmr_proof.subroot_idx >= self.subroots.len() {
            return false; // Subroot index is out of bounds
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
        storage: BTreeMap<(usize, usize), MMRNodeHash>,
        chunks: BTreeMap<MMRNodeHash, MMRChunk>,
        tree_size: usize,
    }

    impl InMemoryStore {
        fn new() -> Self {
            InMemoryStore {
                storage: BTreeMap::new(),
                chunks: BTreeMap::new(),
                tree_size: 0,
            }
        }
    }

    impl NodeStore for InMemoryStore {
        fn save_node(&mut self, level: usize, index: usize, hash: MMRNodeHash) -> Result<()> {
            self.storage.insert((level, index), hash);
            Ok(())
        }

        fn load_node(&self, level: usize, index: usize) -> Result<Option<MMRNodeHash>> {
            Ok(self.storage.get(&(level, index)).cloned())
        }

        fn save_chunk(&mut self, hash: MMRNodeHash, chunk: MMRChunk) -> Result<()> {
            self.chunks.insert(hash, chunk);
            Ok(())
        }

        fn load_chunk(&self, hash: MMRNodeHash) -> Result<Option<MMRChunk>> {
            Ok(self.chunks.get(&hash).cloned())
        }

        fn get_tree_size(&self) -> usize {
            self.tree_size
        }

        fn set_tree_size(&mut self, size: usize) -> Result<()> {
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
            let node = MMRChunk::new(wtxid, body);
            nodes.push(node.clone());

            mmr.append(node).unwrap();

            for j in 0..=i {
                let proof_node = nodes[j as usize].clone();
                let (node, mmr_proof) =
                    mmr.generate_proof(proof_node.wtxid).ok().flatten().unwrap();
                assert!(mmr.verify_proof(node.clone(), &mmr_proof));
            }
        }
    }

    #[test]
    fn test_mmr_native_simple() {
        let store = InMemoryStore::new();
        let mut mmr = MMRNative::new(store.clone());

        let chunk1 = MMRChunk::new([1; 32], vec![10, 20, 30]);
        let chunk2 = MMRChunk::new([2; 32], vec![40, 50, 60]);
        let chunk3 = MMRChunk::new([3; 32], vec![70, 80, 90]);

        mmr.append(chunk1.clone()).unwrap();
        mmr.append(chunk2.clone()).unwrap();
        mmr.append(chunk3.clone()).unwrap();

        let proof = mmr.generate_proof([1; 32]).unwrap();
        assert!(proof.is_some());
        let (chunk, mmr_proof) = proof.unwrap();
        assert_eq!(chunk, chunk1);
        assert!(mmr.verify_proof(chunk, &mmr_proof));
    }

    #[test]
    fn test_native_proof_with_guest_verification() {
        let mut mmr_native = MMRNative::new(InMemoryStore::new());
        let mut mmr_guest = MMRGuest::new();

        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRChunk::new(wtxid, body);

            // Append to both Native and Guest
            mmr_native.append(node.clone()).unwrap();
            mmr_guest.append(node.clone());

            // Generate proof in Native and verify in Guest
            for j in 0..=i {
                let proof_node = MMRChunk::new([j as u8; 32], vec![j as u8; 8]);
                let (_, mmr_proof) = mmr_native
                    .generate_proof(proof_node.wtxid)
                    .ok()
                    .flatten()
                    .unwrap();

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
            let node = MMRChunk::new(wtxid, body);

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
            let node = MMRChunk::new(wtxid, body);
            nodes.push(node.clone());

            mmr_native.append(node.clone()).unwrap();
            mmr_guest.append(node.clone());
        }

        for node in nodes {
            let (_, mmr_proof) = mmr_native
                .generate_proof(node.wtxid)
                .ok()
                .flatten()
                .unwrap();
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
            let node = MMRChunk::new(wtxid, body);
            mmr.append(node).unwrap();
        }

        let mut mmr = MMRNative::new(mmr.store.clone());
        for i in 0..42 {
            let wtxid = [i as u8; 32];
            let body = vec![i as u8; 8];
            let node = MMRChunk::new(wtxid, body);
            let (_, proof) = mmr.generate_proof(wtxid).ok().flatten().unwrap();
            assert!(mmr.verify_proof(node, &proof));
        }
    }
}
