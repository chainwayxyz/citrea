use crate::{Storage, StorageKey, StorageValue};

pub trait StateReader {
    /// Get a value from the storage.
    fn get(&self, key: &StorageKey) -> Option<StorageValue>;
}

pub trait AsReadonly {
    /// Readonly version of the access.
    type Readonly;

    /// Performs the conversion.
    fn as_readonly(&self) -> Self::Readonly;
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
        // TODO propagate witness
        self.inner.get(key, None, Default::default())
    }
}
