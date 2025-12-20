use std::cell::RefCell;
use std::collections::VecDeque;

use super::EcrecoverProviderError;

/// Provides pre-computed addresses zk context
pub struct EcrecoverAddressProvider {
    addresses: RefCell<VecDeque<[u8; 20]>>,
}

impl EcrecoverAddressProvider {
    pub fn new(addresses: VecDeque<[u8; 20]>) -> Self {
        Self {
            addresses: RefCell::new(addresses),
        }
    }

    /// Get the next address
    pub fn get_next(&self) -> Result<[u8; 20], EcrecoverProviderError> {
        self.addresses
            .borrow_mut()
            .pop_front()
            .ok_or(EcrecoverProviderError::NoMoreAddresses)
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl Send for EcrecoverAddressProvider {}
unsafe impl Sync for EcrecoverAddressProvider {}
