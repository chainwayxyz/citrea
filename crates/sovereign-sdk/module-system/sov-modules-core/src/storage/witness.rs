use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
use jmt::proof::{SparseMerkleProof, UpdateMerkleProof};
use sha2::Sha256;

use crate::StorageValue;

/// Witness type to provide values read from storage, and their proof.
#[derive(Default, Debug, BorshDeserialize, BorshSerialize)]
pub struct Witness {
    storage_hints: VecDeque<Option<StorageValue>>,
    state_root_hints: VecDeque<[u8; 32]>,
    read_proof_hints: VecDeque<SparseMerkleProof<Sha256>>,
    update_proof_hints: VecDeque<UpdateMerkleProof<Sha256>>,
}

#[cfg(feature = "native")]
impl Witness {
    /// Add storage hint.
    pub fn add_storage_hint(&mut self, storage_hint: Option<StorageValue>) {
        self.storage_hints.push_back(storage_hint);
    }

    /// Add state root hint.
    pub fn add_state_root_hint(&mut self, state_root_hint: [u8; 32]) {
        self.state_root_hints.push_back(state_root_hint);
    }

    /// Add read proof hint.
    pub fn add_read_proof_hint(&mut self, read_proof_hint: SparseMerkleProof<Sha256>) {
        self.read_proof_hints.push_back(read_proof_hint);
    }

    /// Add update proof hint.
    pub fn add_update_proof_hint(&mut self, update_proof_hint: UpdateMerkleProof<Sha256>) {
        self.update_proof_hints.push_back(update_proof_hint);
    }
}

impl Witness {
    /// Get next storage read hint.
    pub fn get_storage_hint(&mut self) -> Option<StorageValue> {
        self.storage_hints
            .pop_front()
            .expect("No more storage hints left")
    }

    /// Get next state root hint.
    pub fn get_state_root_hint(&mut self) -> [u8; 32] {
        self.state_root_hints
            .pop_front()
            .expect("No more state root hints left")
    }

    /// Get next read proof hint.
    pub fn get_read_proof_hint(&mut self) -> SparseMerkleProof<Sha256> {
        self.read_proof_hints
            .pop_front()
            .expect("No more read proof hints left")
    }

    /// Get next update proof hint.
    pub fn get_update_proof_hint(&mut self) -> UpdateMerkleProof<Sha256> {
        self.update_proof_hints
            .pop_front()
            .expect("No more update proof hints left")
    }
}
