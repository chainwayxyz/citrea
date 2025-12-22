use super::EcrecoverProviderError;
use crate::Secp256k1Pubkey;
use std::cell::RefCell;
use std::collections::VecDeque;

/// Provides pre-computed pubkeys zk context
pub struct RecoveredPubkeyProvider {
    pubkeys: RefCell<VecDeque<Secp256k1Pubkey>>,
}

impl RecoveredPubkeyProvider {
    pub fn new(pubkeys: VecDeque<Secp256k1Pubkey>) -> Self {
        Self {
            pubkeys: RefCell::new(pubkeys),
        }
    }

    /// Get the next address
    pub fn get_next(&self) -> Result<Secp256k1Pubkey, EcrecoverProviderError> {
        self.pubkeys
            .borrow_mut()
            .pop_front()
            .ok_or(EcrecoverProviderError::NoMoreAddresses)
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl Send for RecoveredPubkeyProvider {}
unsafe impl Sync for RecoveredPubkeyProvider {}
