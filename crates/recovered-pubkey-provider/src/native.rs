use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use super::EcrecoverProviderError;
use crate::Secp256k1Pubkey;

thread_local! {
    static PUBKEY_COLLECTION: RefCell<Option<Vec<Secp256k1Pubkey>>> = const { RefCell::new(None) };
}

/// Stateless handle to recovered pubkey collection during native execution.
///
/// All handles share the same thread-local collection for the current thread.
/// Constructing a new handle does not create isolated storage. Collection is
/// opt-in so normal node execution does not accumulate pubkeys in memory.
pub struct RecoveredPubkeyProvider;

/// Keeps recovered pubkey collection active for the current thread.
///
/// `!Send` so it can only be dropped on the thread that started collection,
/// matching the thread-local state it manages.
pub struct RecoveredPubkeyCollectionGuard(PhantomData<Rc<()>>);

impl RecoveredPubkeyCollectionGuard {
    const fn new() -> Self {
        Self(PhantomData)
    }

    /// Take the recorded pubkeys, leaving collection active with an empty buffer.
    #[must_use]
    pub fn take_pubkeys(&self) -> Vec<Secp256k1Pubkey> {
        PUBKEY_COLLECTION.with_borrow_mut(|pubkeys| {
            std::mem::take(
                pubkeys
                    .as_mut()
                    .expect("recovered pubkey collection guard requires active collection"),
            )
        })
    }
}

impl Drop for RecoveredPubkeyCollectionGuard {
    fn drop(&mut self) {
        PUBKEY_COLLECTION.with_borrow_mut(|pubkeys| {
            *pubkeys = None;
        });
    }
}

impl RecoveredPubkeyProvider {
    pub const fn new() -> Self {
        Self
    }

    /// Start collecting recovered pubkeys on the current thread.
    pub fn start_collecting(
        &self,
    ) -> Result<RecoveredPubkeyCollectionGuard, EcrecoverProviderError> {
        PUBKEY_COLLECTION.with_borrow_mut(|pubkeys| {
            if pubkeys.is_some() {
                return Err(EcrecoverProviderError::CollectionAlreadyActive);
            }

            *pubkeys = Some(Vec::new());
            Ok(RecoveredPubkeyCollectionGuard::new())
        })
    }

    /// Whether recovered pubkeys are being collected on the current thread.
    pub fn is_collecting(&self) -> bool {
        PUBKEY_COLLECTION.with_borrow(Option::is_some)
    }

    /// Record a recovered pubkey in deterministic order.
    ///
    /// The batch prover must start collection before replaying L2 blocks.
    pub fn record(&self, pubkey_bytes: Secp256k1Pubkey) -> Result<(), EcrecoverProviderError> {
        PUBKEY_COLLECTION.with_borrow_mut(|pubkeys| {
            let Some(pubkeys) = pubkeys.as_mut() else {
                return Err(EcrecoverProviderError::CollectionNotActive);
            };

            pubkeys.push(pubkey_bytes);
            Ok(())
        })
    }
}

impl Default for RecoveredPubkeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn record_requires_active_collection() {
        let provider = RecoveredPubkeyProvider::new();

        assert!(matches!(
            provider.record([1; 65]),
            Err(EcrecoverProviderError::CollectionNotActive)
        ));
    }

    #[test]
    fn collection_guard_clears_pubkeys_on_drop() {
        let provider = RecoveredPubkeyProvider::new();

        {
            let _guard = provider.start_collecting().unwrap();
            provider.record([1; 65]).unwrap();
        }

        let collection = provider.start_collecting().unwrap();
        assert!(collection.take_pubkeys().is_empty());
    }

    #[test]
    fn take_pubkeys_drains_without_stopping_collection() {
        let provider = RecoveredPubkeyProvider::new();
        let collection = provider.start_collecting().unwrap();

        provider.record([1; 65]).unwrap();
        assert_eq!(collection.take_pubkeys(), vec![[1; 65]]);
        assert!(provider.is_collecting());

        provider.record([2; 65]).unwrap();
        assert_eq!(collection.take_pubkeys(), vec![[2; 65]]);
    }

    #[test]
    fn is_collecting_tracks_guard_lifetime() {
        let provider = RecoveredPubkeyProvider::new();

        assert!(!provider.is_collecting());
        {
            let _guard = provider.start_collecting().unwrap();
            assert!(provider.is_collecting());
        }
        assert!(!provider.is_collecting());
    }

    #[test]
    fn collection_is_thread_local() {
        let provider = Arc::new(RecoveredPubkeyProvider::new());
        let collection = provider.start_collecting().unwrap();

        provider.record([1; 65]).unwrap();

        let thread_provider = Arc::clone(&provider);
        let thread_pubkeys = std::thread::spawn(move || {
            assert!(!thread_provider.is_collecting());

            let collection = thread_provider.start_collecting().unwrap();
            thread_provider.record([3; 65]).unwrap();
            collection.take_pubkeys()
        })
        .join()
        .unwrap();

        assert_eq!(thread_pubkeys, vec![[3; 65]]);
        assert_eq!(collection.take_pubkeys(), vec![[1; 65]]);
    }

    #[test]
    fn rejects_nested_collection_on_same_thread() {
        let provider = RecoveredPubkeyProvider::new();

        let _guard = provider.start_collecting().unwrap();

        assert!(matches!(
            provider.start_collecting(),
            Err(EcrecoverProviderError::CollectionAlreadyActive)
        ));
    }
}
