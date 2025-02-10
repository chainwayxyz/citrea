use std::collections::BTreeMap;

use anyhow::Result;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::{hash_pair, MMRChunk, MMRInclusionProof, MMRNodeHash, NodeStore, Wtxid};

#[derive(
    Default, Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize,
)]
pub struct MMRNative<S: NodeStore> {
    pub store: S,
    pub cache: BTreeMap<(u32, u32), MMRNodeHash>,
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
        self.store.save_chunk(hash, chunk)?;
        let current_size = self.store.get_tree_size();
        self.store.save_node(0, current_size, hash)?;
        self.cache.insert((0, current_size), hash);
        self.store.set_tree_size(current_size + 1)?;
        self.recalculate_peaks()?;
        Ok(())
    }

    pub fn contains(&mut self, wtxid: Wtxid) -> Result<bool> {
        self.find_chunk_index_with_wtxid(wtxid)
            .map(|idx| idx.is_some())
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
        let Some(index) = self.find_chunk_index_with_wtxid(wtxid)? else {
            return Ok(None);
        };

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

        let chunk = self
            .store
            .load_chunk(self.store.load_node(0, index)?.expect("Should be found"))?
            .expect("Should be found");

        let (subroot_idx, internal_idx) = self.get_helpers_from_index(index);
        let mmr_proof = MMRInclusionProof::new(subroot_idx, internal_idx, proof);

        Ok(Some((chunk, mmr_proof)))
    }

    fn load_node(&mut self, level: u32, index: u32) -> Result<Option<MMRNodeHash>> {
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

    // TODO: Could be implemented better
    fn find_chunk_index_with_wtxid(&mut self, wtxid: Wtxid) -> Result<Option<u32>> {
        let size = self.store.get_tree_size();
        for i in 0..size {
            if let Some(node_hash) = self.load_node(0, i)? {
                if let Some(chunk) = self.store.load_chunk(node_hash)? {
                    if chunk.wtxid == wtxid {
                        return Ok(Some(i));
                    }
                }
            }
        }
        Ok(None)
    }

    fn get_helpers_from_index(&self, index: u32) -> (u32, u32) {
        let xor = self.store.get_tree_size() ^ index;
        let xor_leading_digit = 31 - xor.leading_zeros();
        let internal_idx = index & ((1 << xor_leading_digit) - 1);
        let leading_zeros_size = 31 - self.store.get_tree_size().leading_zeros();
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
        subroots[mmr_proof.subroot_idx as usize] == subroot
    }

    pub(crate) fn get_subroots(&mut self) -> Vec<MMRNodeHash> {
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
