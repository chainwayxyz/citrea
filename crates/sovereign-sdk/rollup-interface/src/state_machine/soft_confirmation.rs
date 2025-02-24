//! Defines traits and types used by the rollup to verify claims about the
//! soft confirmation

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};

/// Soft confirmation header
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Header {
    l2_height: u64,
    da_slot_txs_commitment: [u8; 32],
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
        l2_height: u64,
        da_slot_txs_commitment: [u8; 32],
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        l1_fee_rate: u128,
        tx_merkle_root: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            l2_height,
            da_slot_txs_commitment,
            prev_hash,
            state_root,
            l1_fee_rate,
            tx_merkle_root,
            timestamp,
        }
    }

    /// Compute soft confirmation header digest
    pub fn compute_digest<D: Digest>(&self) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(self.l2_height.to_be_bytes());
        hasher.update(self.da_slot_txs_commitment);
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
/// and hash checking against PreFork2 *SoftConfirmations structs.
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Block<'txs, Tx: Clone + BorshSerialize> {
    /// Header
    pub header: SignedL2Header,
    /// Txs of signed batch
    pub txs: Cow<'txs, [Tx]>,
    /// Deposit data
    /// TODO remove before mainnet
    pub deposit_data: Vec<Vec<u8>>,
    /// L1 height
    /// TODO remove before mainnet
    pub da_slot_height: u64,
    /// L1 hash
    /// TODO remove before mainnet
    pub da_slot_hash: [u8; 32],
}

impl<'txs, Tx: Clone + BorshSerialize> L2Block<'txs, Tx> {
    /// New L2Block from headers and txs
    pub fn new(
        header: SignedL2Header,
        txs: Cow<'txs, [Tx]>,
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> Self {
        Self {
            header,
            txs,
            deposit_data,
            da_slot_hash,
            da_slot_height,
        }
    }

    /// L2 block height
    pub fn l2_height(&self) -> u64 {
        self.header.inner.l2_height
    }

    /// Hash of the signed batch
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash
    }

    /// Hash of the previous signed batch
    pub fn prev_hash(&self) -> [u8; 32] {
        self.header.inner.prev_hash
    }

    /// DA block this soft confirmation was given for
    pub fn da_slot_height(&self) -> u64 {
        self.da_slot_height
    }

    /// DA block to build on
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }

    /// DA block transactions commitment
    pub fn da_slot_txs_commitment(&self) -> [u8; 32] {
        self.header.inner.da_slot_txs_commitment
    }

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.header.pub_key.as_ref()
    }

    /// Deposit data
    pub fn deposit_data(&self) -> &[Vec<u8>] {
        self.deposit_data.as_slice()
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

    /// Borsh serialize all txs as blobs
    /// Required for backward compatiblity
    fn compute_blobs(&self) -> Vec<Vec<u8>> {
        self.txs
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect()
    }

    /// Serialized L2Block in a Genesis compatible way
    pub fn serialize_v1<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.l2_height(), writer)?;
        BorshSerialize::serialize(&self.hash(), writer)?;
        BorshSerialize::serialize(&self.prev_hash(), writer)?;
        BorshSerialize::serialize(&self.da_slot_height(), writer)?;
        BorshSerialize::serialize(&self.da_slot_hash(), writer)?;
        BorshSerialize::serialize(&self.da_slot_txs_commitment(), writer)?;
        BorshSerialize::serialize(&self.l1_fee_rate(), writer)?;
        BorshSerialize::serialize(&self.compute_blobs(), writer)?;
        BorshSerialize::serialize(&self.signature().to_vec(), writer)?;
        BorshSerialize::serialize(&self.deposit_data().to_vec(), writer)?;
        BorshSerialize::serialize(&self.pub_key().to_vec(), writer)?;
        BorshSerialize::serialize(&self.timestamp(), writer)
    }

    /// Serialized L2Block in a Kumquat compatible way
    pub fn serialize_v2<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.l2_height(), writer)?;
        BorshSerialize::serialize(&self.hash(), writer)?;
        BorshSerialize::serialize(&self.prev_hash(), writer)?;
        BorshSerialize::serialize(&self.da_slot_height(), writer)?;
        BorshSerialize::serialize(&self.da_slot_hash(), writer)?;
        BorshSerialize::serialize(&self.da_slot_txs_commitment(), writer)?;
        BorshSerialize::serialize(&self.l1_fee_rate(), writer)?;
        BorshSerialize::serialize(&self.compute_blobs(), writer)?;
        BorshSerialize::serialize(&self.txs, writer)?;
        BorshSerialize::serialize(&self.signature().to_vec(), writer)?;
        BorshSerialize::serialize(&self.deposit_data().to_vec(), writer)?;
        BorshSerialize::serialize(&self.pub_key().to_vec(), writer)?;
        BorshSerialize::serialize(&self.timestamp(), writer)
    }
}

/// Contains raw transactions and information about the soft confirmation block
#[derive(Debug, PartialEq, BorshSerialize, Clone)]
pub struct UnsignedSoftConfirmation<'txs, Tx> {
    l2_height: u64,
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    blobs: Vec<Vec<u8>>,
    txs: &'txs [Tx],
    deposit_data: Vec<Vec<u8>>,
    l1_fee_rate: u128,
    timestamp: u64,
}

impl<'txs, Tx: BorshSerialize> UnsignedSoftConfirmation<'txs, Tx> {
    /// Create UnsignedSoftConfirmation from header and required for backwards compatibility fields
    pub fn new(
        header: &L2Header,
        blobs: Vec<Vec<u8>>,
        txs: &'txs [Tx],
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> Self {
        UnsignedSoftConfirmation {
            l2_height: header.l2_height,
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs,
            txs,
            deposit_data,
            l1_fee_rate: header.l1_fee_rate,
            timestamp: header.timestamp,
        }
    }

    /// Compute digest for the whole UnsignedSoftConfirmation struct
    pub fn compute_digest<D: Digest>(&self) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(self.l2_height.to_be_bytes());
        hasher.update(self.da_slot_height.to_be_bytes());
        hasher.update(self.da_slot_hash);
        hasher.update(self.da_slot_txs_commitment);
        for tx in &self.blobs {
            hasher.update(tx);
        }
        for deposit in &self.deposit_data {
            hasher.update(deposit);
        }
        hasher.update(self.l1_fee_rate.to_be_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.finalize()
    }
}

/// Old version of UnsignedSoftConfirmation
/// Used for backwards compatibility
/// Always use ```UnsignedSoftConfirmation``` instead
#[derive(BorshSerialize)]
pub struct UnsignedSoftConfirmationV1 {
    l2_height: u64,
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    blobs: Vec<Vec<u8>>,
    deposit_data: Vec<Vec<u8>>,
    l1_fee_rate: u128,
    timestamp: u64,
}

impl<'txs, Tx: Clone + BorshSerialize> From<&'txs L2Block<'_, Tx>>
    for UnsignedSoftConfirmation<'txs, Tx>
{
    fn from(block: &'txs L2Block<'_, Tx>) -> Self {
        let header = &block.header.inner;
        Self {
            l2_height: header.l2_height,
            da_slot_height: block.da_slot_height(),
            da_slot_hash: block.da_slot_hash(),
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs: block.compute_blobs(),
            txs: &block.txs,
            deposit_data: block.deposit_data.clone(),
            l1_fee_rate: header.l1_fee_rate,
            timestamp: header.timestamp,
        }
    }
}

impl<'txs, Tx: Clone + BorshSerialize> From<&'txs L2Block<'_, Tx>> for UnsignedSoftConfirmationV1 {
    fn from(block: &'txs L2Block<'_, Tx>) -> Self {
        let header = &block.header.inner;
        Self {
            l2_height: header.l2_height,
            da_slot_height: block.da_slot_height(),
            da_slot_hash: block.da_slot_hash(),
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs: block.compute_blobs(),
            deposit_data: block.deposit_data.clone(),
            l1_fee_rate: header.l1_fee_rate,
            timestamp: header.timestamp,
        }
    }
}

impl UnsignedSoftConfirmationV1 {
    /// Create UnsignedSoftConfirmation from header and required for backwards compatibility fields
    pub fn new(
        header: &L2Header,
        blobs: Vec<Vec<u8>>,
        deposit_data: Vec<Vec<u8>>,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
    ) -> Self {
        UnsignedSoftConfirmationV1 {
            l2_height: header.l2_height,
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs,
            deposit_data,
            l1_fee_rate: header.l1_fee_rate,
            timestamp: header.timestamp,
        }
    }

    /// Pre fork1 version of compute_digest
    // TODO: Remove derive(BorshSerialize) for UnsignedSoftConfirmation
    //   when removing this fn
    // FIXME: ^
    pub fn hash<D: Digest>(&self) -> Output<D> {
        let raw = borsh::to_vec(&self).unwrap();
        D::digest(raw.as_slice())
    }
}
