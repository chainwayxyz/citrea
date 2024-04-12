//! Defines traits and types used by the rollup to verify claims about the
//! soft confirmation

use alloc::vec::Vec;
use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Contains raw transactions and information about the soft confirmation block
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct UnsignedSoftConfirmationBatch {
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    pre_state_root: Vec<u8>,
    txs: Vec<Vec<u8>>,
    l1_fee_rate: u64,
    timestamp: u64,
}

impl UnsignedSoftConfirmationBatch {
    /// Creates a new unsigned soft confirmation batch
    pub fn new(
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
        da_slot_txs_commitment: [u8; 32],
        pre_state_root: Vec<u8>,
        txs: Vec<Vec<u8>>,
        l1_fee_rate: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment,
            pre_state_root,
            txs,
            l1_fee_rate,
            timestamp,
        }
    }
    /// DA block to build on
    pub fn da_slot_height(&self) -> u64 {
        self.da_slot_height
    }
    /// DA block hash
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }
    /// DA block transactions commitment
    pub fn da_slot_txs_commitment(&self) -> [u8; 32] {
        self.da_slot_txs_commitment
    }
    /// Previous batch's pre state root
    pub fn pre_state_root(&self) -> Vec<u8> {
        self.pre_state_root.clone()
    }
    /// Raw transactions.
    pub fn txs(&self) -> Vec<Vec<u8>> {
        self.txs.clone()
    }
    /// Base layer fee rate sats/wei etc. per byte.
    pub fn l1_fee_rate(&self) -> u64 {
        self.l1_fee_rate
    }
    /// Sequencer block timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// Signed version of the `UnsignedSoftConfirmationBatch`
/// Contains the signature and public key of the sequencer
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct SignedSoftConfirmationBatch {
    hash: [u8; 32],
    da_slot_height: u64,
    da_slot_hash: [u8; 32],
    da_slot_txs_commitment: [u8; 32],
    pre_state_root: Vec<u8>,
    l1_fee_rate: u64,
    txs: Vec<Vec<u8>>,
    signature: Vec<u8>,
    pub_key: Vec<u8>,
    timestamp: u64,
}

impl SignedSoftConfirmationBatch {
    /// Creates a signed soft confirmation batch
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hash: [u8; 32],
        da_slot_height: u64,
        da_slot_hash: [u8; 32],
        da_slot_txs_commitment: [u8; 32],
        pre_state_root: Vec<u8>,
        l1_fee_rate: u64,
        txs: Vec<Vec<u8>>,
        signature: Vec<u8>,
        pub_key: Vec<u8>,
        timestamp: u64,
    ) -> SignedSoftConfirmationBatch {
        Self {
            hash,
            da_slot_height,
            da_slot_hash,
            da_slot_txs_commitment,
            pre_state_root,
            l1_fee_rate,
            txs,
            signature,
            pub_key,
            timestamp,
        }
    }

    /// Hash of the unsigned batch
    pub fn hash(&self) -> [u8; 32] {
        self.hash
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
        self.da_slot_txs_commitment
    }

    /// Previous batch's pre state root
    pub fn pre_state_root(&self) -> Vec<u8> {
        self.pre_state_root.clone()
    }

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Txs of signed batch
    pub fn txs(&self) -> Vec<Vec<u8>> {
        self.txs.clone()
    }

    /// Signature of the sequencer
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    /// Borsh serialized data
    pub fn full_data(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap()
    }

    /// L1 fee rate
    pub fn l1_fee_rate(&self) -> u64 {
        self.l1_fee_rate
    }

    /// Public key of sequencer
    pub fn pub_key(&self) -> Vec<u8> {
        self.pub_key.clone()
    }

    /// Sets l1 fee rate
    pub fn set_l1_fee_rate(&mut self, l1_fee_rate: u64) {
        self.l1_fee_rate = l1_fee_rate;
    }

    /// Sets da slot hash
    pub fn set_da_slot_hash(&mut self, da_slot_hash: [u8; 32]) {
        self.da_slot_hash = da_slot_hash;
    }

    /// Sequencer block timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}
