use parking_lot::Mutex;

use super::EcrecoverProviderError;
use crate::Secp256k1Pubkey;

/// Collects ecrecover pubkeys during native execution in deterministic order.
///
/// Addresses are recorded during transaction recovery and later extracted to be
/// included inside the input
pub struct RecoveredPubkeyProvider {
    pubkeys: Mutex<Vec<Secp256k1Pubkey>>,
}

impl RecoveredPubkeyProvider {
    pub fn new() -> Self {
        Self {
            pubkeys: Mutex::new(Vec::new()),
        }
    }

    /// Record a recovered pubkey bytes in deterministic order
    pub fn record(&self, pubkey_bytes: Secp256k1Pubkey) {
        self.pubkeys.lock().push(pubkey_bytes);
    }

    /// Clear all recorded pubkeys
    pub fn clear(&self) {
        self.pubkeys.lock().clear();
    }

    /// Take all recorded pubkeys and clear the internal buffer
    pub fn take_pubkeys(&self) -> Result<Vec<Secp256k1Pubkey>, EcrecoverProviderError> {
        let mut vec = self.pubkeys.lock();
        Ok(std::mem::take(&mut *vec))
    }
}

impl Default for RecoveredPubkeyProvider {
    fn default() -> Self {
        Self::new()
    }
}
