use std::cell::RefCell;
use std::collections::VecDeque;

use super::{EcrecoverAddressProvider, EcrecoverProviderError};

/// Provides pre-computed addresses zk context
pub struct ZkEcrecoverAddressProvider {
    addresses: RefCell<VecDeque<[u8; 20]>>,
}

impl ZkEcrecoverAddressProvider {
    pub fn new(addresses: VecDeque<[u8; 20]>) -> Self {
        Self {
            addresses: RefCell::new(addresses),
        }
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl Send for ZkEcrecoverAddressProvider {}
unsafe impl Sync for ZkEcrecoverAddressProvider {}

impl EcrecoverAddressProvider for ZkEcrecoverAddressProvider {
    /// Record a recovered address
    fn record(&self, _address: [u8; 20]) {
        unimplemented!("record is not implemented for ZkEcrecoverAddressProvider");
    }

    /// Clear all recorded addresses
    fn clear(&self) {
        unimplemented!("clear is not implemented for ZkEcrecoverAddressProvider");
    }

    /// Take addresses
    fn take_addresses(&self) -> Result<Vec<[u8; 20]>, EcrecoverProviderError> {
        unimplemented!("take_addresses is not implemented for ZkEcrecoverAddressProvider");
    }

    /// Get the next address from the witness
    fn get_next(&self) -> Result<[u8; 20], EcrecoverProviderError> {
        self.addresses
            .borrow_mut()
            .pop_front()
            .ok_or(EcrecoverProviderError::NoMoreAddresses)
    }
}
