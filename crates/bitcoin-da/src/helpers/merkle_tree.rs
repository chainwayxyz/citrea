//! Bitcoin merkle tree implementation.
//! Code is taken from Clementine
//! https://github.com/chainwayxyz/clementine/blob/b600ea18df72bdc60015ded01b78131b4c9121d7/operator/src/bitcoin_merkle.rs

use super::calculate_double_sha256;

/// Bitcoin merkle tree.
#[derive(Debug, Clone)]
pub struct BitcoinMerkleTree {
    /// Inner nodes.
    nodes: Vec<Vec<[u8; 32]>>,
}

impl BitcoinMerkleTree {
    /// Compute merkle tree.
    pub fn new(transactions: Vec<[u8; 32]>) -> Self {
        if transactions.len() == 1 {
            // root is the coinbase txid
            return BitcoinMerkleTree {
                nodes: vec![transactions],
            };
        }

        let mut tree = BitcoinMerkleTree {
            nodes: vec![transactions],
        };

        // Construct the tree
        let mut curr_level_offset: usize = 1;
        let mut prev_level_size = tree.nodes[0].len();
        let mut preimage: [u8; 64] = [0; 64];

        // Continue building the tree until we reach a level with only one node (the root)
        while prev_level_size > 1 {
            tree.nodes.push(vec![]);

            // Process each pair of nodes from the previous level
            for i in 0..(prev_level_size / 2) {
                let l = &tree.nodes[curr_level_offset - 1][i * 2];
                let r = &tree.nodes[curr_level_offset - 1][i * 2 + 1];
                // Check if the pair has the same digest, if so, panic
                assert_ne!(
                    l, r,
                    "Duplicate hashes in the Merkle tree, indicating mutation"
                );
                preimage[..32].copy_from_slice(l);
                preimage[32..].copy_from_slice(r);
                let combined_hash = calculate_double_sha256(&preimage);
                // Add the parent node's hash to the current level
                tree.nodes[curr_level_offset].push(combined_hash);
            }

            // Handle the case where the previous level had an odd number of nodes
            if prev_level_size % 2 == 1 {
                // In Bitcoin's Merkle tree, if a level has an odd number of nodes,
                // the last node is duplicated when calculating its parent
                // Copy the last node's hash into both halves of the preimage
                preimage[..32]
                    .copy_from_slice(&tree.nodes[curr_level_offset - 1][prev_level_size - 1]);
                preimage.copy_within(..32, 32);
                // Calculate the parent node's hash
                let combined_hash = calculate_double_sha256(&preimage);
                // Add the parent node's hash to the current level
                tree.nodes[curr_level_offset].push(combined_hash);
            }
            curr_level_offset += 1;
            // Calculate the size of the level we just created
            prev_level_size = (prev_level_size + 1) / 2; // Ceiling division to handle odd numbers
        }
        tree
    }

    /// Returns the Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.nodes[self.nodes.len() - 1][0]
    }

    #[cfg(feature = "native")]
    /// Get path by the index
    pub fn get_idx_path(&self, index: u32) -> Vec<[u8; 32]> {
        assert!(index < self.nodes[0].len() as u32, "Index out of bounds");
        let mut path = vec![];
        let mut level = 0;
        let mut i = index;
        while level < self.nodes.len() as u32 - 1 {
            if i % 2 == 1 {
                path.push(self.nodes[level as usize][i as usize - 1]);
            } else if (self.nodes[level as usize].len() - 1) as u32 == i {
                path.push(self.nodes[level as usize][i as usize]);
            } else {
                path.push(self.nodes[level as usize][(i + 1) as usize]);
            }
            level += 1;
            i /= 2;
        }
        path
    }

    /// It recomputes the Merkle root using
    /// - a leaf hash
    /// - a Merkle proof (list of sibling hashes along the path)
    /// - an index indicating left/right sibling order at each level
    pub fn calculate_root_with_merkle_proof(
        txid: [u8; 32],
        idx: u32,
        merkle_proof: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut preimage: [u8; 64] = [0; 64];
        let mut combined_hash: [u8; 32] = txid;
        let mut index = idx;
        let mut level: u32 = 0;
        while level < merkle_proof.len() as u32 {
            if index % 2 == 0 {
                preimage[..32].copy_from_slice(&combined_hash);
                preimage[32..].copy_from_slice(&merkle_proof[level as usize]);
                combined_hash = calculate_double_sha256(&preimage);
            } else {
                let left = &merkle_proof[level as usize];
                if left == &combined_hash {
                    panic!("Merkle proof is invalid: left hash matches combined hash");
                }
                preimage[..32].copy_from_slice(left);
                preimage[32..].copy_from_slice(&combined_hash);
                combined_hash = calculate_double_sha256(&preimage);
            }
            level += 1;
            index /= 2;
        }
        combined_hash
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;
    use crate::helpers::calculate_wtxid;
    use crate::helpers::parsers::parse_hex_transaction;

    #[test]
    fn test_merkle_root_with_proof() {
        let mut transactions: Vec<[u8; 32]> = vec![];
        for i in 0u8..100u8 {
            let tx = [i; 32];
            transactions.push(tx);
        }
        let tree = BitcoinMerkleTree::new(transactions.clone());
        let root = tree.root();
        let idx_path = tree.get_idx_path(0);
        let calculated_root =
            BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[0], 0, &idx_path);
        assert_eq!(root, calculated_root);
    }

    #[test]
    /// a b c
    /// but try to cheat and say c is index 3
    #[should_panic(expected = "Merkle proof is invalid: left hash matches combined hash")]
    fn test_merkle_root_with_proof_wrong_idx_a() {
        let mut transactions: Vec<[u8; 32]> = vec![];
        for i in 0u8..3u8 {
            let tx = [i; 32];
            transactions.push(tx);
        }
        let tree = BitcoinMerkleTree::new(transactions.clone());
        let root = tree.root();
        let idx_path = tree.get_idx_path(2);
        let calculated_root =
            BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[2], 2, &idx_path);
        assert_eq!(root, calculated_root);

        BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[2], 3, &idx_path);
    }
    #[test]
    /// a b c d e f
    /// but try to cheat and say e is index 6
    #[should_panic(expected = "Merkle proof is invalid: left hash matches combined hash")]
    fn test_merkle_root_with_proof_wrong_idx_b() {
        let mut transactions: Vec<[u8; 32]> = vec![];
        for i in 0u8..6u8 {
            let tx = [i; 32];
            transactions.push(tx);
        }
        let tree = BitcoinMerkleTree::new(transactions.clone());
        let root = tree.root();
        let idx_path = tree.get_idx_path(4);
        let calculated_root =
            BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[4], 4, &idx_path);
        assert_eq!(root, calculated_root);

        BitcoinMerkleTree::calculate_root_with_merkle_proof(transactions[4], 6, &idx_path);
    }

    #[test]
    fn test_merkle_tree_single_tx() {
        let tx = [5; 32];
        assert_eq!(BitcoinMerkleTree::new(vec![tx]).root(), tx);
    }

    #[test]
    fn test_merkle_tree_against_bitcoin_impl() {
        let txs = std::fs::read_to_string("test_data/mock_txs.txt")
            .unwrap()
            .lines()
            .map(|tx_hex| parse_hex_transaction(tx_hex).unwrap())
            .map(|tx| calculate_wtxid(&tx))
            .collect::<Vec<_>>();
        compare_merkle_tree_against_bitcoin_impl(txs);
    }

    fn compare_merkle_tree_against_bitcoin_impl(transactions: Vec<[u8; 32]>) {
        let hashes = transactions
            .iter()
            .map(|tx| bitcoin::hash_types::Wtxid::from_slice(tx).unwrap());
        let bitcoin_root = bitcoin::merkle_tree::calculate_root(hashes).unwrap();

        let custom_root = BitcoinMerkleTree::new(transactions).root();
        assert_eq!(bitcoin_root.to_byte_array(), custom_root);
    }

    #[test]
    fn test_merkle_tree_against_bitcoin_impl_2361() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        let d = [4; 32];
        let e = [5; 32];
        let f = [6; 32];

        compare_merkle_tree_against_bitcoin_impl(vec![a]);
        compare_merkle_tree_against_bitcoin_impl(vec![a, b]);
        compare_merkle_tree_against_bitcoin_impl(vec![a, b, c]);
        compare_merkle_tree_against_bitcoin_impl(vec![a, b, c, d]);
        compare_merkle_tree_against_bitcoin_impl(vec![a, b, c, d, e]);
        compare_merkle_tree_against_bitcoin_impl(vec![a, b, c, d, e, f]);
    }

    #[test]
    #[should_panic(expected = "Duplicate hashes in the Merkle tree, indicating mutation")]
    fn test_merkle_duplicates_a_2361() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        let d = [4; 32];
        let e = [5; 32];

        BitcoinMerkleTree::new(vec![a, b, c, d, e, e]);
    }

    #[test]
    #[should_panic(expected = "Duplicate hashes in the Merkle tree, indicating mutation")]
    fn test_merkle_duplicates_b_2361() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        let d = [4; 32];
        let e = [5; 32];
        let f = [6; 32];

        BitcoinMerkleTree::new(vec![a, b, c, d, e, f, e, f]);
    }

    #[test]
    #[should_panic(expected = "Duplicate hashes in the Merkle tree, indicating mutation")]
    fn test_merkle_duplicates_c_2361() {
        let a = [1; 32];
        let b = [2; 32];
        let c = [3; 32];
        let d = [4; 32];
        let e = [5; 32];
        let f = [6; 32];

        BitcoinMerkleTree::new(vec![a, b, c, d, a, b, c, d, e, f]);
    }
}
