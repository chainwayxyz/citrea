//! Defines traits and types used by the rollup to verify claims about the
//! soft confirmation

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::maybestd::vec::Vec;

/// Contains raw transactions and information about the soft confirmation block
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct UnsignedSoftConfirmationBatch {
    /// DA block to build on
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// Previous batch's post state root
    pub pre_state_root: Vec<u8>,
    /// Raw transactions.
    pub txs: Vec<Vec<u8>>,
}

/// Signed version of the `UnsignedSoftConfirmationBatch`
/// Contains the signature and public key of the sequencer
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct SignedSoftConfirmationBatch {
    /// Hash of the unsigned batch
    pub hash: [u8; 32],
    /// DA block this soft confirmation was given for
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// Previous batch's post state root
    pub pre_state_root: Vec<u8>,
    /// Raw transactions.
    pub txs: Vec<Vec<u8>>,
    /// Signature
    pub signature: Vec<u8>,
    /// Public key of signer
    pub pub_key: Vec<u8>,
}

impl SignedSoftConfirmationBatch {
    /// Hash of the unsigned batch
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// DA block to build on
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }

    /// Previous batch's post state root
    pub fn pre_state_root(&self) -> Vec<u8> {
        self.pre_state_root.clone()
    }

    /// Public key of signer
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Borsh serialized data
    pub fn full_data(&mut self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }
}
