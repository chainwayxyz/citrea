use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
use jmt::proof::{SparseMerkleProof, UpdateMerkleProof};
use sha2::Sha256;

use crate::StorageValue;

/// Witness type to provide values read from storage, and their proof.
#[derive(Default, Debug, BorshDeserialize, BorshSerialize)]
pub struct Witness {
    storage_hints: VecDeque<Option<StorageValue>>,
    state_root_hints: [[u8; 32]; 2],
    read_proof_hints: VecDeque<SparseMerkleProof<Sha256>>,
    update_proof_hint: Option<UpdateMerkleProof<Sha256>>,
}

#[cfg(feature = "native")]
impl Witness {
    /// Add storage hint.
    pub fn add_storage_hint(&mut self, storage_hint: Option<StorageValue>) {
        self.storage_hints.push_back(storage_hint);
    }

    /// Add prev state root hint.
    pub fn add_prev_state_root_hint(&mut self, prev_state_root: [u8; 32]) {
        self.state_root_hints[0] = prev_state_root;
    }

    /// Add final state root hint.
    pub fn add_final_state_root_hint(&mut self, final_state_root: [u8; 32]) {
        self.state_root_hints[1] = final_state_root;
    }

    /// Add read proof hint.
    pub fn add_read_proof_hint(&mut self, read_proof_hint: SparseMerkleProof<Sha256>) {
        self.read_proof_hints.push_back(read_proof_hint);
    }

    /// Add update proof hint.
    pub fn add_update_proof_hint(&mut self, update_proof_hint: UpdateMerkleProof<Sha256>) {
        assert!(self.update_proof_hint.is_none(), "Must not add update proof twice");
        self.update_proof_hint = Some(update_proof_hint);
    }
}

impl Witness {
    /// Get next storage read hint.
    pub fn get_storage_hint(&mut self) -> Option<StorageValue> {
        self.storage_hints
            .pop_front()
            .expect("No more storage hints left")
    }

    /// Get prev state root hint.
    pub fn get_prev_state_root_hint(&mut self) -> [u8; 32] {
        self.state_root_hints[0]
    }

    /// Get finalstate root hint.
    pub fn get_final_state_root_hint(&mut self) -> [u8; 32] {
        self.state_root_hints[1]
    }

    /// Get next read proof hint.
    pub fn get_read_proof_hint(&mut self) -> SparseMerkleProof<Sha256> {
        self.read_proof_hints
            .pop_front()
            .expect("No more read proof hints left")
    }

    /// Get next update proof hint.
    pub fn get_update_proof_hint(&mut self) -> UpdateMerkleProof<Sha256> {
        self.update_proof_hint.take().expect("No update proof found")
    }
}
