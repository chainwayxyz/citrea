//! Defines traits and types used by the rollup to verify claims about the
//! soft confirmation

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
struct UnsignedSoftConfirmationBatch {
    /// DA block to build on
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// Previous batch's post state root
    pub pre_state_root: [u8; 32],
    /// Raw transactions.
    pub txs: Vec<Vec<u8>>,
}

/// Contains raw transactions and information about the soft confirmation block
#[derive(Debug, PartialEq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize, Eq)]
pub struct SignedSoftConfirmationBatch {
    /// DA block to build on
    pub da_slot_height: u64,
    /// DA block hash
    pub da_slot_hash: [u8; 32],
    /// Previous batch's post state root
    pub pre_state_root: [u8; 32],
    /// Raw transactions.
    pub txs: Vec<Vec<u8>>,
    /// Signature
    pub signature: [u8; 32],
    /// Public key of signer
    pub pub_key: [u8; 32],
}

impl SignedSoftConfirmationBatch {
    /// TODO
    pub fn da_slot_hash(&self) -> [u8; 32] {
        self.da_slot_hash
    }

    /// TODO
    pub fn pre_state_root(&self) -> [u8; 32] {
        self.pre_state_root
    }

    /// TODO
    pub fn sequencer_pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// TODO
    pub fn hash(&self) -> [u8; 32] {
        todo!()
    }

    /// TODO
    pub fn full_data(&mut self) -> Vec<u8> {
        self.try_to_vec().unwrap()
    }

    /// TODO
    pub fn verify_signature(&self) -> Result<(), anyhow::Error> {
        todo!("verify_signature")
        // let unsigned = UnsignedSoftConfirmationBatch {
        //     da_slot_height: self.da_slot_height.clone(),
        //     da_slot_hash: self.da_slot_hash.clone(),
        //     pre_state_root: self.pre_state_root.clone(),
        //     txs: self.txs.clone(),
        // };

        // let message = unsigned.try_to_vec().unwrap();

        // // self.pub_key.verify(&message, &self.signature)?;

        // Ok(())
    }
}
