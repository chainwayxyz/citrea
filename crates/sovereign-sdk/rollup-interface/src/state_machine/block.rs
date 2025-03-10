//! Defines traits and types used by the rollup to verify claims about the
//! l2 block

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};

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
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct SignedL2Header {
    /// L2 header
    pub inner: L2Header,
    /// Header hash
    pub hash: [u8; 32],
    /// Header signature
    pub signature: Vec<u8>,
    /// Sequencer pub key
    pub pub_key: Vec<u8>,
}

impl SignedL2Header {
    /// Crate new L2Block from header, hash and signature
    pub fn new(header: L2Header, hash: [u8; 32], signature: Vec<u8>, pub_key: Vec<u8>) -> Self {
        Self {
            inner: header,
            hash,
            signature,
            pub_key,
        }
    }
}

/// Signed L2 block
/// `blobs`, `deposit_data`, `da_slot_height` and `da_slot_hash` are kept for compatibility reason
/// and hash checking against PreFork2 *L2Blocks structs.
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Block<'txs, Tx: Clone + BorshSerialize> {
    /// Header
    pub header: SignedL2Header,
    /// Txs of signed batch
    pub txs: Cow<'txs, [Tx]>,
}

impl<'txs, Tx: Clone + BorshSerialize> L2Block<'txs, Tx> {
    /// New L2Block from headers and txs
    pub fn new(header: SignedL2Header, txs: Cow<'txs, [Tx]>) -> Self {
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

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.header.pub_key.as_ref()
    }

    /// Signature of the sequencer
    pub fn signature(&self) -> &[u8] {
        self.header.signature.as_slice()
    }

    /// L1 fee rate
    pub fn l1_fee_rate(&self) -> u128 {
        self.header.inner.l1_fee_rate
    }

    /// Public key of sequencer
    pub fn pub_key(&self) -> &[u8] {
        self.header.pub_key.as_slice()
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
