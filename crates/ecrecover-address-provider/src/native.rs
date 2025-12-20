use parking_lot::Mutex;

use super::EcrecoverProviderError;

/// Collects ecrecover addresses during native execution in deterministic order.
///
/// Addresses are recorded during transaction recovery and later extracted to be
/// included inside the input
pub struct EcrecoverAddressProvider {
    addresses: Mutex<Vec<[u8; 20]>>,
}

impl EcrecoverAddressProvider {
    pub fn new() -> Self {
        Self {
            addresses: Mutex::new(Vec::new()),
        }
    }

    /// Record a recovered address in deterministic order
    pub fn record(&self, address: [u8; 20]) {
        self.addresses.lock().push(address);
    }

    /// Clear all recorded addresses
    pub fn clear(&self) {
        self.addresses.lock().clear();
    }

    /// Take all recorded addresses and clear the internal buffer
    pub fn take_addresses(&self) -> Result<Vec<[u8; 20]>, EcrecoverProviderError> {
        let mut vec = self.addresses.lock();
        Ok(std::mem::take(&mut *vec))
    }
}

impl Default for EcrecoverAddressProvider {
    fn default() -> Self {
        Self::new()
    }
}
