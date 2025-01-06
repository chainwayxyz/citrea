use std::collections::BTreeMap;

use super::*;

#[derive(Clone)]
struct InMemoryStore {
    storage: BTreeMap<(u32, u32), MMRNodeHash>,
    chunks: BTreeMap<MMRNodeHash, MMRChunk>,
    tree_size: u32,
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
            let (node, mmr_proof) = mmr.generate_proof(proof_node.wtxid).ok().flatten().unwrap();
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
