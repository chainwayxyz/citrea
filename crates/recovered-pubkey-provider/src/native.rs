use parking_lot::Mutex;

use super::EcrecoverProviderError;

/// Collects ecrecover addresses during native execution in deterministic order.
///
/// Addresses are recorded during transaction recovery and later extracted to be
/// included inside the input
pub struct RecoveredPubkeyProvider {
    addresses: Mutex<Vec<Vec<u8>>>,
}

impl RecoveredPubkeyProvider {
    pub fn new() -> Self {
        Self {
            addresses: Mutex::new(Vec::new()),
        }
    }

    /// Record a recovered pubkey bytes in deterministic order
    pub fn record(&self, pubkey_bytes: Vec<u8>) {
        self.addresses.lock().push(pubkey_bytes);
    }

    /// Clear all recorded addresses
    pub fn clear(&self) {
        self.addresses.lock().clear();
    }

    /// Take all recorded pubkeys and clear the internal buffer
    pub fn take_pubkeys(&self) -> Result<Vec<Vec<u8>>, EcrecoverProviderError> {
        let mut vec = self.addresses.lock();
        Ok(std::mem::take(&mut *vec))
    }
}

impl Default for RecoveredPubkeyProvider {
    fn default() -> Self {
        Self::new()
    }
}
