use parking_lot::Mutex;

use super::{EcrecoverAddressProvider, EcrecoverProviderError};

/// Collects ecrecover addresses during native execution in deterministic order
pub struct NativeEcrecoverAddressCollector {
    addresses: Mutex<Vec<[u8; 20]>>,
}

impl NativeEcrecoverAddressCollector {
    pub fn new() -> Self {
        Self {
            addresses: Mutex::new(Vec::new()),
        }
    }
}

impl Default for NativeEcrecoverAddressCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl EcrecoverAddressProvider for NativeEcrecoverAddressCollector {
    /// Record a recovered address in deterministic order
    fn record(&self, address: [u8; 20]) {
        self.addresses.lock().push(address);
    }

    /// Clear all recorded addresses
    fn clear(&self) {
        self.addresses.lock().clear();
    }

    /// Take all recorded addresses and clear the internal buffer
    fn take_addresses(&self) -> Result<Vec<[u8; 20]>, EcrecoverProviderError> {
        let mut vec = self.addresses.lock();
        Ok(std::mem::take(&mut *vec))
    }

    /// Get the next address from witness (not implemented for native)
    fn get_next(&self) -> Result<[u8; 20], EcrecoverProviderError> {
        unimplemented!("get_next is not implemented for NativeEcrecoverAddressCollector");
    }
}
