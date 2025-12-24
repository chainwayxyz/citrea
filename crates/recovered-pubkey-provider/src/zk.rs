use std::cell::RefCell;

use super::EcrecoverProviderError;
use crate::Secp256k1Pubkey;

/// Provides pre-computed pubkeys zk context
pub struct RecoveredPubkeyProvider {
    pubkeys: RefCell<std::vec::IntoIter<Secp256k1Pubkey>>,
}

impl RecoveredPubkeyProvider {
    pub fn new(pubkeys: Vec<Secp256k1Pubkey>) -> Self {
        Self {
            pubkeys: RefCell::new(pubkeys.into_iter()),
        }
    }

    /// Get the next address
    pub fn get_next(&self) -> Result<Secp256k1Pubkey, EcrecoverProviderError> {
        self.pubkeys
            .borrow_mut()
            .next()
            .ok_or(EcrecoverProviderError::NoMoreAddresses)
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl Send for RecoveredPubkeyProvider {}
unsafe impl Sync for RecoveredPubkeyProvider {}
