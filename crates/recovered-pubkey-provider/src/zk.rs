use std::cell::RefCell;
use std::collections::VecDeque;

use super::EcrecoverProviderError;

/// Provides pre-computed pubkeys zk context
pub struct RecoveredPubkeyProvider {
    pubkeys: RefCell<VecDeque<Vec<u8>>>,
}

impl RecoveredPubkeyProvider {
    pub fn new(pubkeys: VecDeque<Vec<u8>>) -> Self {
        Self {
            pubkeys: RefCell::new(pubkeys),
        }
    }

    /// Get the next address
    pub fn get_next(&self) -> Result<Vec<u8>, EcrecoverProviderError> {
        self.pubkeys
            .borrow_mut()
            .pop_front()
            .ok_or(EcrecoverProviderError::NoMoreAddresses)
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl Send for RecoveredPubkeyProvider {}
unsafe impl Sync for RecoveredPubkeyProvider {}
