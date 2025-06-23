//! Defines traits and types used by the rollup to verify claims about the
//! l2 block

use borsh::{BorshDeserialize, BorshSerialize};
use digest::{Digest, FixedOutput};
use serde::{Deserialize, Serialize};

use super::transaction::Transaction;

/// Represents the header of an L2 block in the rollup system.
/// Contains essential metadata about the block including its height,
/// cryptographic hashes, and fee information.
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Header {
    /// The block height/number in the L2 chain
    height: u64,
    /// Hash of the previous block in the chain
    prev_hash: [u8; 32],
    /// Merkle root of the state tree after applying this block's transactions
    state_root: [u8; 32],
    /// Fee rate for L1 transactions associated with this block
    l1_fee_rate: u128,
    /// Merkle root of all transactions included in this block
    tx_merkle_root: [u8; 32],
    /// Unix timestamp when this block was created
    timestamp: u64,
}

impl L2Header {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new L2 block header with the specified parameters.
    ///
    /// # Arguments
    /// * `height` - The block height/number
    /// * `prev_hash` - Hash of the previous block
    /// * `state_root` - Merkle root of the state tree
    /// * `l1_fee_rate` - Fee rate for L1 transactions
    /// * `tx_merkle_root` - Merkle root of block transactions
    /// * `timestamp` - Block creation timestamp
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

    /// Returns the merkle root of the state tree after applying this block's transactions.
    pub fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    /// Computes the cryptographic digest of the block header using the specified hash function.
    ///
    /// # Type Parameters
    /// * `D` - The type of hash function to use (must implement the `Digest` trait)
    ///
    /// # Returns
    /// The computed hash digest of the header
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.height.to_be_bytes());
        hasher.update(self.prev_hash);
        hasher.update(self.state_root);
        hasher.update(self.l1_fee_rate.to_be_bytes());
        hasher.update(self.tx_merkle_root);
        hasher.update(self.timestamp.to_be_bytes());
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}

/// Represents a signed L2 block header, containing the header itself along with
/// its cryptographic hash and a signature from the sequencer.
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct SignedL2Header {
    /// The L2 block header
    pub inner: L2Header,
    /// Cryptographic hash of the header
    pub hash: [u8; 32],
    /// Digital signature of the header by the sequencer
    pub signature: Vec<u8>,
}

impl SignedL2Header {
    /// Creates a new signed L2 block header.
    ///
    /// # Arguments
    /// * `header` - The L2 block header
    /// * `hash` - Cryptographic hash of the header
    /// * `signature` - Digital signature of the header
    pub fn new(header: L2Header, hash: [u8; 32], signature: Vec<u8>) -> Self {
        Self {
            inner: header,
            hash,
            signature,
        }
    }
}

/// Represents a complete L2 block in the rollup system.
/// Contains a signed header and the list of transactions included in the block.
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct L2Block {
    /// The signed block header
    pub header: SignedL2Header,
    /// List of transactions included in this block
    pub txs: Vec<Transaction>,
}

impl L2Block {
    /// Creates a new L2 block.
    ///
    /// # Arguments
    /// * `header` - The signed block header
    /// * `txs` - List of transactions to include in the block
    pub fn new(header: SignedL2Header, txs: Vec<Transaction>) -> Self {
        Self { header, txs }
    }

    /// Returns the height/number of this block in the L2 chain.
    pub fn height(&self) -> u64 {
        self.header.inner.height
    }

    /// Returns the cryptographic hash of this block.
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash
    }

    /// Returns the hash of the previous block in the chain.
    pub fn prev_hash(&self) -> [u8; 32] {
        self.header.inner.prev_hash
    }

    /// Returns the sequencer's signature of this block.
    pub fn signature(&self) -> &[u8] {
        self.header.signature.as_slice()
    }

    /// Returns the L1 fee rate associated with this block.
    pub fn l1_fee_rate(&self) -> u128 {
        self.header.inner.l1_fee_rate
    }

    /// Returns the timestamp when this block was created.
    pub fn timestamp(&self) -> u64 {
        self.header.inner.timestamp
    }

    /// Returns the merkle root of all transactions in this block.
    pub fn tx_merkle_root(&self) -> [u8; 32] {
        self.header.inner.tx_merkle_root
    }

    /// Returns the merkle root of the state tree after applying this block's transactions.
    pub fn state_root(&self) -> [u8; 32] {
        self.header.inner.state_root
    }
}
