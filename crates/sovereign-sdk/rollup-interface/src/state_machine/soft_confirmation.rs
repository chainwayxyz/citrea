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
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
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
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
        da_slot_txs_commitment: [u8; 32],
        prev_hash: [u8; 32],
        state_root: [u8; 32],
        l1_fee_rate: u128,
        tx_merkle_root: [u8; 32],
        timestamp: u64,
    ) -> Self {
        Self {
            l2_height,
            da_slot_height,
            da_slot_hash,
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
        hasher.update(self.da_slot_height.to_be_bytes());
        hasher.update(self.da_slot_hash);
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
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
pub struct L2Block<'txs, Tx: Clone + BorshSerialize> {
    /// Header
    pub header: SignedL2Header,
    /// Txs of signed batch
    pub txs: Cow<'txs, [Tx]>,
    /// Blobs of signed batch
    pub blobs: Cow<'txs, [Vec<u8>]>,
    /// Deposit data
    pub deposit_data: Vec<Vec<u8>>,
}

impl<'txs, Tx: Clone + BorshSerialize> L2Block<'txs, Tx> {
    /// New L2Block from headers and txs
    pub fn new(
        header: SignedL2Header,
        txs: Cow<'txs, [Tx]>,
        blobs: Cow<'txs, [Vec<u8>]>,
        deposit_data: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            header,
            txs,
            blobs,
            deposit_data,
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
        self.header.inner.da_slot_height
    }

    /// DA block to build on
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.header.inner.da_slot_hash
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

    /// Sets l1 fee rate
    pub fn set_l1_fee_rate(&mut self, l1_fee_rate: u128) {
        self.header.inner.l1_fee_rate = l1_fee_rate;
    }

    /// Sets da slot hash
    pub fn set_da_slot_hash(&mut self, da_slot_hash: [u8; 32]) {
        self.header.inner.da_slot_hash = da_slot_hash;
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

impl<'txs, Tx: BorshSerialize> From<(&L2Header, Vec<Vec<u8>>, &'txs [Tx], Vec<Vec<u8>>)>
    for UnsignedSoftConfirmation<'txs, Tx>
{
    fn from(
        (header, blobs, txs, deposit_data): (&L2Header, Vec<Vec<u8>>, &'txs [Tx], Vec<Vec<u8>>),
    ) -> Self {
        UnsignedSoftConfirmation::new(
            header.l2_height,
            header.da_slot_height,
            header.da_slot_hash,
            header.da_slot_txs_commitment,
            blobs,
            txs,
            deposit_data,
            header.l1_fee_rate,
            header.timestamp,
        )
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

impl<'txs, Tx: BorshSerialize> UnsignedSoftConfirmation<'txs, Tx> {
    #[allow(clippy::too_many_arguments)]
    /// Creates a new unsigned soft confirmation batch
    pub fn new(
        l2_height: u64,
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
        da_slot_txs_commitment: [u8; 32],
        blobs: Vec<Vec<u8>>,
        txs: &'txs [Tx],
        deposit_data: Vec<Vec<u8>>,
        l1_fee_rate: u128,
        timestamp: u64,
    ) -> Self {
        Self {
            l2_height,
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment,
            blobs,
            txs,
            deposit_data,
            l1_fee_rate,
            timestamp,
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

impl<'txs, Tx: Clone + BorshSerialize> From<&'txs L2Block<'_, Tx>>
    for UnsignedSoftConfirmation<'txs, Tx>
{
    fn from(block: &'txs L2Block<'_, Tx>) -> Self {
        let header = &block.header.inner;
        Self {
            l2_height: header.l2_height,
            da_slot_height: header.da_slot_height,
            da_slot_hash: header.da_slot_hash,
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs: block.blobs.to_vec(),
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
            da_slot_height: header.da_slot_height,
            da_slot_hash: header.da_slot_hash,
            da_slot_txs_commitment: header.da_slot_txs_commitment,
            blobs: block.blobs.to_vec(),
            deposit_data: block.deposit_data.clone(),
            l1_fee_rate: header.l1_fee_rate,
            timestamp: header.timestamp,
        }
    }
}

impl<'txs, Tx: BorshSerialize> From<UnsignedSoftConfirmation<'txs, Tx>>
    for UnsignedSoftConfirmationV1
{
    fn from(value: UnsignedSoftConfirmation<Tx>) -> Self {
        UnsignedSoftConfirmationV1 {
            l2_height: value.l2_height,
            da_slot_height: value.da_slot_height,
            da_slot_hash: value.da_slot_hash,
            da_slot_txs_commitment: value.da_slot_txs_commitment,
            blobs: value.blobs,
            deposit_data: value.deposit_data,
            l1_fee_rate: value.l1_fee_rate,
            timestamp: value.timestamp,
        }
    }
}

impl UnsignedSoftConfirmationV1 {
    /// Pre fork1 version of compute_digest
    // TODO: Remove derive(BorshSerialize) for UnsignedSoftConfirmation
    //   when removing this fn
    // FIXME: ^
    pub fn hash<D: Digest>(&self) -> Output<D> {
        let raw = borsh::to_vec(&self).unwrap();
        D::digest(raw.as_slice())
    }
}

/// Signed version of the `UnsignedSoftConfirmation`
/// Contains the signature and public key of the sequencer
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct SignedSoftConfirmation<'txs, Tx: Clone + BorshSerialize> {
    l2_height: u64,
    hash: [u8; 32],
    prev_hash: [u8; 32],
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    l1_fee_rate: u128,
    blobs: Cow<'txs, [Vec<u8>]>,
    txs: Cow<'txs, [Tx]>,
    signature: Vec<u8>,
    deposit_data: Vec<Vec<u8>>,
    pub_key: Vec<u8>,
    timestamp: u64,
}

impl<'txs, Tx: Clone + BorshSerialize> SignedSoftConfirmation<'txs, Tx> {
    /// Creates a signed soft confirmation batch
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        l2_height: u64,
        hash: [u8; 32],
        prev_hash: [u8; 32],
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
        da_slot_txs_commitment: [u8; 32],
        l1_fee_rate: u128,
        blobs: Cow<'txs, [Vec<u8>]>,
        txs: Cow<'txs, [Tx]>,
        deposit_data: Vec<Vec<u8>>,
        signature: Vec<u8>,
        pub_key: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            l2_height,
            hash,
            prev_hash,
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment,
            l1_fee_rate,
            blobs,
            txs,
            deposit_data,
            signature,
            pub_key,
            timestamp,
        }
    }
}

/// Signed version of the `UnsignedSoftConfirmation` used in Genesis
/// Contains the signature and public key of the sequencer
#[derive(PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct SignedSoftConfirmationV1 {
    l2_height: u64,
    hash: [u8; 32],
    prev_hash: [u8; 32],
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    l1_fee_rate: u128,
    txs: Vec<Vec<u8>>,
    signature: Vec<u8>,
    deposit_data: Vec<Vec<u8>>,
    pub_key: Vec<u8>,
    timestamp: u64,
}

impl<'txs, Tx: Clone + BorshSerialize> From<SignedSoftConfirmation<'txs, Tx>>
    for SignedSoftConfirmationV1
{
    fn from(input: SignedSoftConfirmation<'txs, Tx>) -> Self {
        SignedSoftConfirmationV1 {
            l2_height: input.l2_height,
            hash: input.hash,
            prev_hash: input.prev_hash,
            da_slot_height: input.da_slot_height,
            da_slot_hash: input.da_slot_hash,
            da_slot_txs_commitment: input.da_slot_txs_commitment,
            l1_fee_rate: input.l1_fee_rate,
            txs: input.blobs.into_owned(),
            signature: input.signature,
            deposit_data: input.deposit_data,
            pub_key: input.pub_key,
            timestamp: input.timestamp,
        }
    }
}

impl<'txs, Tx: Clone + BorshSerialize> From<L2Block<'_, Tx>> for SignedSoftConfirmation<'txs, Tx> {
    fn from(input: L2Block<'_, Tx>) -> Self {
        SignedSoftConfirmation {
            l2_height: input.l2_height(),
            hash: input.hash(),
            prev_hash: input.prev_hash(),
            da_slot_height: input.da_slot_height(),
            da_slot_hash: input.da_slot_hash(),
            da_slot_txs_commitment: input.da_slot_txs_commitment(),
            l1_fee_rate: input.l1_fee_rate(),
            blobs: Cow::Owned(input.blobs.to_vec()),
            txs: Cow::Owned(input.txs.to_vec()),
            signature: input.signature().to_vec(),
            deposit_data: input.deposit_data().to_vec(),
            pub_key: input.pub_key().to_vec(),
            timestamp: input.timestamp(),
        }
    }
}

impl<Tx: Clone + BorshSerialize> From<L2Block<'_, Tx>> for SignedSoftConfirmationV1 {
    fn from(input: L2Block<'_, Tx>) -> Self {
        SignedSoftConfirmationV1 {
            l2_height: input.l2_height(),
            hash: input.hash(),
            prev_hash: input.prev_hash(),
            da_slot_height: input.da_slot_height(),
            da_slot_hash: input.da_slot_hash(),
            da_slot_txs_commitment: input.da_slot_txs_commitment(),
            l1_fee_rate: input.l1_fee_rate(),
            txs: input.blobs.to_vec(),
            signature: input.signature().to_vec(),
            deposit_data: input.deposit_data().to_vec(),
            pub_key: input.pub_key().to_vec(),
            timestamp: input.timestamp(),
        }
    }
}
