/// Code is taken from Clementine
/// https://github.com/chainwayxyz/clementine/blob/b600ea18df72bdc60015ded01b78131b4c9121d7/operator/src/bitcoin_merkle.rs
///
use super::calculate_double_sha256;

#[derive(Debug, Clone)]
pub struct BitcoinMerkleTree {
    depth: u32,
    nodes: Vec<Vec<[u8; 32]>>,
}

impl BitcoinMerkleTree {
    pub fn new(transactions: Vec<[u8; 32]>) -> Self {
        if transactions.len() == 0 {
            return BitcoinMerkleTree {
                depth: 0,
                nodes: vec![],
            };
        }
        if transactions.len() == 1 {
            // root is the coinbase txid
            return BitcoinMerkleTree {
                depth: 1,
                nodes: vec![transactions],
            };
        }

        let depth = (transactions.len() - 1).ilog(2) + 1;
        let mut tree = BitcoinMerkleTree {
            depth,
            nodes: vec![transactions],
        };

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = tree.nodes[0].len();
        let mut prev_level_index_offset = 0;
        let mut preimage: [u8; 64] = [0; 64];
        while prev_level_size > 1 {
            tree.nodes.push(vec![]);
            for i in 0..(prev_level_size / 2) {
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1 as usize][prev_level_index_offset + i * 2],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1][prev_level_index_offset + i * 2 + 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            if prev_level_size % 2 == 1 {
                let mut preimage: [u8; 64] = [0; 64];
                preimage[..32].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                preimage[32..].copy_from_slice(
                    &tree.nodes[curr_level_offset - 1]
                        [prev_level_index_offset + prev_level_size - 1],
                );
                let combined_hash = calculate_double_sha256(&preimage);
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            prev_level_size = (prev_level_size + 1) / 2;
            prev_level_index_offset = 0;
        }
        tree
    }

    // Returns the Merkle root
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.nodes.len() == 0 {
            return None;
        }
        return Some(self.nodes[self.nodes.len() - 1][0]);
    }

    pub fn get_element(&self, level: u32, index: u32) -> [u8; 32] {
        return self.nodes[level as usize][index as usize];
    }

    pub fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(
            index <= self.nodes[0].len() as u32 - 1,
            "Index out of bounds"
        );
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;
        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else {
                if (self.nodes[level as usize].len() - 1) as u32 == i {
                    path.push(self.nodes[level as usize][i as usize]);
                } else {
                    path.push(self.nodes[level as usize][(i + 1) as usize]);
                }
            }
            level += 1;
            i = i / 2;
        }
        return path;
    }

    pub fn calculate_root_with_merkle_proof(
        txid: [u8; 32],
        idx: u32,
        merkle_proof: Vec<[u8; 32]>,
    ) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = txid.clone();
        let mut index = idx;
        let mut level: u32 = 0;
        while level < merkle_proof.len() as u32 {
            if index % 2 == 0 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                preimage[..32].copy_from_slice(&merkle_proof[level as usize]);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
            index = index / 2;
        }
        combined_hash
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use crate::helpers::test_utils::get_mock_txs;

    use super::*;

    #[test]
    fn test_merkle_root_with_proof() {
        let mut transactions: Vec<[u8; 32]> = vec![];
        for i in 0u8..100u8 {
            let tx = [i; 32];
            transactions.push(tx);
        }
        let tree = BitcoinMerkleTree::new(transactions.clone());
        let root = tree.root().unwrap();
        let idx_path = tree.get_idx_path(0);
        let calculated_root =
            BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[0], 0, idx_path);
        assert_eq!(root, calculated_root);
    }

    #[test]
    fn test_empty_merkle_tree() {
        assert_eq!(BitcoinMerkleTree::new(vec![]).root(), None);
    }

    #[test]
    fn test_merkle_tree_single_tx() {
        let tx = [5; 32];
        assert_eq!(BitcoinMerkleTree::new(vec![tx]).root().unwrap(), tx);
    }

    #[test]
    fn test_merkle_tree_against_bitcoin_impl() {
        compare_merkle_tree_against_bitcoin_impl(vec![[0; 32]; 100]);
        compare_merkle_tree_against_bitcoin_impl(vec![[5; 32]; 10]);
        compare_merkle_tree_against_bitcoin_impl(vec![[255; 32]; 33]);
        compare_merkle_tree_against_bitcoin_impl(vec![[200; 32]; 2]);
        compare_merkle_tree_against_bitcoin_impl(vec![[99; 32]; 1]);

        let txs = get_mock_txs().iter().map(|tx| tx.compute_wtxid().to_byte_array()).collect();
        compare_merkle_tree_against_bitcoin_impl(txs);
    }

    fn compare_merkle_tree_against_bitcoin_impl(transactions: Vec<[u8; 32]>) {
        let hashes = transactions.iter().map(|tx| bitcoin::hash_types::Wtxid::from_slice(tx).unwrap());
        let bitcoin_root = bitcoin::merkle_tree::calculate_root(hashes).unwrap();

        let custom_root = BitcoinMerkleTree::new(transactions).root().unwrap();
        assert_eq!(bitcoin_root.to_byte_array(), custom_root);
    }
}
