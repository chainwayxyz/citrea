use crate::{Storage, StorageKey, StorageValue};

pub trait StateReader {
    /// Get a value from the storage.
    fn get(&self, key: &StorageKey) -> Option<StorageValue>;
}

pub trait AsReadonly {
    /// Readonly version of the access.
    type Readonly;

    /// Performs the conversion.
    fn as_readonly(&self, level: Option<IsolationLevel>) -> Self::Readonly;
}

pub enum IsolationLevel {
    /// Read isolation level.
    ReadCommitted,
    /// Write isolation level.
    DirtyRead,
}

pub struct StateSnapshot<S: Storage> {
    inner: S,
}

impl<S: Storage> StateSnapshot<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: Storage> StateReader for StateSnapshot<S> {
    fn get(&self, key: &StorageKey) -> Option<StorageValue> {
        // TODO propagate witness?
        let witness: S::Witness = Default::default();
        self.inner.get(key, None, &witness)
    }
}
