use std::collections::{HashSet, VecDeque};

use alloy_primitives::keccak256;
use sov_rollup_interface::da::ForcedTransaction;
use tracing::debug;

use crate::metrics::SEQUENCER_METRICS as SM;

/// A mempool for forced transactions extracted from L1 blocks.
/// Forced transactions are user-submitted EVM transactions inscribed on Bitcoin
/// that the sequencer MUST include within a deadline.
#[derive(Clone, Debug, Default)]
pub struct ForcedTxMempool {
    /// Queue of pending forced transactions (FIFO order)
    pending_txs: VecDeque<ForcedTransaction>,
    /// Set of seen tx hashes (keccak256 of rlp_tx) for deduplication
    seen_tx_hashes: HashSet<[u8; 32]>,
}

impl ForcedTxMempool {
    /// Creates a new empty forced transaction mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a forced transaction to the mempool.
    /// Returns true if the transaction was added, false if it was already seen.
    pub fn add(&mut self, ft: ForcedTransaction) -> bool {
        let tx_hash: [u8; 32] = keccak256(&ft.rlp_tx).into();

        if !self.seen_tx_hashes.insert(tx_hash) {
            debug!("Forced transaction already in mempool: {}", hex::encode(tx_hash));
            return false;
        }

        self.pending_txs.push_back(ft);
        SM.forced_tx_mempool_txs.set(self.pending_txs.len() as f64);
        true
    }

    /// Fetches up to `limit` forced transactions from the front of the queue
    /// without removing them.
    pub fn fetch(&self, limit: usize) -> Vec<ForcedTransaction> {
        self.pending_txs
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Removes the given forced transactions from the mempool after successful inclusion.
    pub fn remove(&mut self, txs: &[ForcedTransaction]) {
        let hashes_to_remove: HashSet<[u8; 32]> = txs
            .iter()
            .map(|ft| keccak256(&ft.rlp_tx).into())
            .collect();

        self.pending_txs.retain(|ft| {
            let hash: [u8; 32] = keccak256(&ft.rlp_tx).into();
            !hashes_to_remove.contains(&hash)
        });

        SM.forced_tx_mempool_txs.set(self.pending_txs.len() as f64);
    }

    /// Returns the number of pending forced transactions.
    pub fn len(&self) -> usize {
        self.pending_txs.len()
    }

    /// Returns true if the mempool has no pending forced transactions.
    pub fn is_empty(&self) -> bool {
        self.pending_txs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ft(rlp: &[u8], height: u64) -> ForcedTransaction {
        ForcedTransaction {
            rlp_tx: rlp.to_vec(),
            l1_block_height: height,
        }
    }

    #[test]
    fn test_add_and_fetch() {
        let mut mempool = ForcedTxMempool::new();
        let ft1 = make_ft(b"tx1", 100);
        let ft2 = make_ft(b"tx2", 101);

        assert!(mempool.add(ft1.clone()));
        assert!(mempool.add(ft2.clone()));
        assert_eq!(mempool.len(), 2);

        let fetched = mempool.fetch(1);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].rlp_tx, b"tx1");

        let fetched_all = mempool.fetch(10);
        assert_eq!(fetched_all.len(), 2);
    }

    #[test]
    fn test_dedup() {
        let mut mempool = ForcedTxMempool::new();
        let ft = make_ft(b"tx1", 100);

        assert!(mempool.add(ft.clone()));
        assert!(!mempool.add(ft.clone()));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut mempool = ForcedTxMempool::new();
        let ft1 = make_ft(b"tx1", 100);
        let ft2 = make_ft(b"tx2", 101);
        let ft3 = make_ft(b"tx3", 102);

        mempool.add(ft1.clone());
        mempool.add(ft2.clone());
        mempool.add(ft3.clone());

        mempool.remove(&[ft1, ft2]);
        assert_eq!(mempool.len(), 1);
        assert_eq!(mempool.fetch(10)[0].rlp_tx, b"tx3");
    }

    #[test]
    fn test_fifo_order() {
        let mut mempool = ForcedTxMempool::new();
        let ft1 = make_ft(b"first", 100);
        let ft2 = make_ft(b"second", 101);
        let ft3 = make_ft(b"third", 102);

        mempool.add(ft1);
        mempool.add(ft2);
        mempool.add(ft3);

        let fetched = mempool.fetch(3);
        assert_eq!(fetched[0].rlp_tx, b"first");
        assert_eq!(fetched[1].rlp_tx, b"second");
        assert_eq!(fetched[2].rlp_tx, b"third");
    }
}
