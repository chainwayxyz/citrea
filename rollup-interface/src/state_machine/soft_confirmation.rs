//! Defines traits and types used by the rollup to verify claims about the
//! soft confirmation

use core::fmt::Debug;

/// A specification of a soft confirmation batch.
pub trait SoftConfirmationSpec: 'static + Debug + PartialEq + Eq + Clone {
    /// Returns DA layer hash
    fn da_slot_hash(&self) -> [u8; 32];

    /// Returns previous state root
    fn pre_state_root(&self) -> [u8; 32];

    /// Returns sequencers public key
    fn sequencer_pub_key(&self) -> &[u8];

    /// Returns hash of the batch
    fn hash(&self) -> [u8; 32];

    /// Returns borsh serialized batch
    #[cfg(feature = "native")]
    fn full_data(&mut self) -> Vec<u8>;

    /// Verifies the sequencer signature
    fn verify_signature(&self) -> Result<(), anyhow::Error>;
}
