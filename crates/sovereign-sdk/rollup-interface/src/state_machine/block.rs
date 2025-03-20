//! Defines traits and types used by the rollup to verify claims about the
//! l2 block

use borsh::{BorshDeserialize, BorshSerialize};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};

use super::transaction::Transaction;

/// L2 block header
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Header {
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    l1_fee_rate: u128,
    tx_merkle_root: [u8; 32],
    timestamp: u64,
}

impl L2Header {
    #[allow(clippy::too_many_arguments)]
    /// New L2Header
    pub fn new(
        height: u64,
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        l1_fee_rate: u128,
        tx_merkle_root: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            height,
            prev_hash,
            state_root,
            l1_fee_rate,
            tx_merkle_root,
            timestamp,
        }
    }

    /// Compute l2 block header digest
    pub fn compute_digest<D: Digest>(&self) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_root);
        hasher.update(self.l1_fee_rate.to_be_bytes());
        hasher.update(self.tx_merkle_root);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.finalize()
    }
}

/// Signed L2 header
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct SignedL2Header {
    /// L2 header
    pub inner: L2Header,
    /// Header hash
    pub hash: [u8; 32],
    /// Header signature
    pub signature: Vec<u8>,
}

impl SignedL2Header {
    /// Crate new L2Block from header, hash and signature
    pub fn new(header: L2Header, hash: [u8; 32], signature: Vec<u8>) -> Self {
        Self {
            inner: header,
            hash,
            signature,
        }
    }
}

/// Signed L2 block
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct L2Block {
    /// Header
    pub header: SignedL2Header,
    /// Txs of signed batch
    pub txs: Vec<Transaction>,
}

impl L2Block {
    /// New L2Block from headers and txs
    pub fn new(header: SignedL2Header, txs: Vec<Transaction>) -> Self {
        Self { header, txs }
    }

    /// L2 block height
    pub fn height(&self) -> u64 {
        self.header.inner.height
    }

    /// Hash of the signed batch
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash
    }

    /// Hash of the previous signed batch
    pub fn prev_hash(&self) -> [u8; 32] {
        self.header.inner.prev_hash
    }

    /// Signature of the sequencer
    pub fn signature(&self) -> &[u8] {
        self.header.signature.as_slice()
    }

    /// L1 fee rate
    pub fn l1_fee_rate(&self) -> u128 {
        self.header.inner.l1_fee_rate
    }

    /// Sequencer block timestamp
    pub fn timestamp(&self) -> u64 {
        self.header.inner.timestamp
    }
    /// Tx merkle root
    pub fn tx_merkle_root(&self) -> [u8; 32] {
        self.header.inner.tx_merkle_root
    }

    /// state root
    pub fn state_root(&self) -> [u8; 32] {
        self.header.inner.state_root
    }
}
