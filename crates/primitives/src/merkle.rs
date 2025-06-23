use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_rollup_interface::transaction::Transaction;

use crate::EMPTY_TX_ROOT;

pub fn compute_tx_hashes(txs: &[Transaction]) -> Vec<[u8; 32]> {
    txs.iter().map(|tx| tx.compute_digest()).collect()
}

pub fn compute_tx_merkle_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return EMPTY_TX_ROOT;
    }

    MerkleTree::<Sha256>::from_leaves(tx_hashes)
        .root()
        .expect("Couldn't compute merkle root")
}

pub fn verify_tx_merkle_root(txs: &[Transaction], root: [u8; 32]) -> bool {
    // Calculate tx hashes for merkle root
    let tx_hashes = compute_tx_hashes(txs);
    let tx_merkle_root = compute_tx_merkle_root(&tx_hashes);

    tx_merkle_root != root
}
