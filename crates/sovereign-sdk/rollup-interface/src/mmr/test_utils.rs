use std::collections::BTreeMap;

use super::*;

#[derive(Clone, Default)]
pub struct InMemoryStore {
    storage: BTreeMap<(u32, u32), MMRNodeHash>,
    chunks: BTreeMap<MMRNodeHash, MMRChunk>,
    tree_size: u32,
}

impl NodeStore for InMemoryStore {
    fn save_node(&mut self, level: u32, index: u32, hash: MMRNodeHash) -> Result<()> {
        self.storage.insert((level, index), hash);
        Ok(())
    }

    fn load_node(&self, level: u32, index: u32) -> Result<Option<MMRNodeHash>> {
        Ok(self.storage.get(&(level, index)).cloned())
    }

    fn save_chunk(&mut self, hash: MMRNodeHash, chunk: MMRChunk) -> Result<()> {
        self.chunks.insert(hash, chunk);
        Ok(())
    }

    fn load_chunk(&self, hash: MMRNodeHash) -> Result<Option<MMRChunk>> {
        Ok(self.chunks.get(&hash).cloned())
    }

    fn get_tree_size(&self) -> u32 {
        self.tree_size
    }

    fn set_tree_size(&mut self, size: u32) -> Result<()> {
        self.tree_size = size;
        Ok(())
    }
}
