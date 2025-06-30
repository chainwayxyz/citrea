use rs_merkle::algorithms::Sha256 as Sha256WithoutSeparator;
use rs_merkle::MerkleTree;
use sha2::digest::{Digest, FixedOutput};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::transaction::Transaction;

use crate::EMPTY_TX_ROOT;

pub fn compute_tx_hashes(txs: &[Transaction], spec: SpecId) -> Vec<[u8; 32]> {
    let digest_fn = if spec >= SpecId::Fork3 {
        |tx: &Transaction| {
            // rehash with separator
            let hash = tx.compute_digest();
            let mut hasher = sha2::Sha256::new_with_prefix([0]);
            hasher.update(hash);
            <[u8; 32]>::from(hasher.finalize_fixed())
        }
    } else {
        |tx: &Transaction| tx.compute_digest()
    };
    txs.iter().map(digest_fn).collect()
}

pub fn compute_tx_merkle_root(tx_hashes: &[[u8; 32]], spec: SpecId) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return EMPTY_TX_ROOT;
    }

    #[derive(Clone)]
    pub struct Sha256WithSeparator {}

    impl rs_merkle::Hasher for Sha256WithSeparator {
        type Hash = [u8; 32];

        fn hash(data: &[u8]) -> [u8; 32] {
            let mut hasher = sha2::Sha256::new_with_prefix([1]);

            hasher.update(data);
            <[u8; 32]>::from(hasher.finalize_fixed())
        }
    }

    if spec >= SpecId::Fork3 {
        MerkleTree::<Sha256WithSeparator>::from_leaves(tx_hashes)
            .root()
            .expect("Couldn't compute merkle root")
    } else {
        MerkleTree::<Sha256WithoutSeparator>::from_leaves(tx_hashes)
            .root()
            .expect("Couldn't compute merkle root")
    }
}

pub fn verify_tx_merkle_root(txs: &[Transaction], root: [u8; 32], spec: SpecId) -> bool {
    // Calculate tx hashes for merkle root
    let tx_hashes = compute_tx_hashes(txs, spec);
    let tx_merkle_root = compute_tx_merkle_root(&tx_hashes, spec);

    tx_merkle_root == root
}
