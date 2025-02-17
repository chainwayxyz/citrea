//! Bytes prefix definition.

use alloc::vec::Vec;
use core::{fmt, str};

use sha2::Digest;

use crate::module::Context;

/// A prefix prepended to each key before insertion and retrieval from the storage.
///
/// When interacting with state containers, you will usually use the same working set instance to
/// access them, as required by the module API. This also means that you might get key collisions,
/// so it becomes necessary to prepend a prefix to each key.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(
    feature = "sync",
    derive(
        serde::Serialize,
        serde::Deserialize,
        borsh::BorshDeserialize,
        borsh::BorshSerialize
    )
)]
pub struct Prefix {
    prefix: Vec<u8>,
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let buf = self.prefix.as_ref();
        match str::from_utf8(buf) {
            Ok(s) => {
                write!(f, "{:?}", s)
            }
            Err(_) => {
                write!(f, "0x{}", hex::encode(buf))
            }
        }
    }
}

impl Extend<u8> for Prefix {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.prefix.extend(iter)
    }
}

impl Prefix {
    /// Creates a new prefix from a byte vector.
    pub fn new(prefix: Vec<u8>) -> Self {
        Self { prefix }
    }

    /// Returns a reference to the vector containing the prefix.
    pub fn as_vec(&self) -> &Vec<u8> {
        &self.prefix
    }

    /// Returns a clone of the vector containing the prefix.
    pub fn to_vec(&self) -> Vec<u8> {
        self.prefix.clone()
    }

    /// Returns the length in bytes of the prefix.
    pub fn len(&self) -> usize {
        self.prefix.len()
    }

    /// Returns `true` if the prefix is empty, `false` otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefix.is_empty()
    }

    /// Returns a new prefix allocated on the fly, by extending the current
    /// prefix with the given bytes.
    pub fn extended(&self, bytes: &[u8]) -> Self {
        let mut new_prefix = Vec::with_capacity(self.len() + bytes.len());
        new_prefix.extend_from_slice(self.as_vec());
        new_prefix.extend_from_slice(bytes);

        Self::new(new_prefix)
    }
}

// separator == "/"
const DOMAIN_SEPARATOR: [u8; 1] = [47];

/// A unique identifier for each state variable in a module.
#[derive(Debug, PartialEq, Eq)]
pub struct ModulePrefix {
    module_path: &'static str,
    module_name: &'static str,
    storage_name: Option<&'static str>,
}

impl ModulePrefix {
    /// Creates a new instance of a module prefix with the provided static definitions.
    pub fn new_storage(
        module_path: &'static str,
        module_name: &'static str,
        storage_name: &'static str,
    ) -> Self {
        Self {
            module_path,
            module_name,
            storage_name: Some(storage_name),
        }
    }

    /// Creates a new instance without a storage name.
    pub fn new_module(module_path: &'static str, module_name: &'static str) -> Self {
        Self {
            module_path,
            module_name,
            storage_name: None,
        }
    }

    fn combine_prefix(&self) -> Vec<u8> {
        let storage_name_len = self
            .storage_name
            .map(|name| name.len() + DOMAIN_SEPARATOR.len())
            .unwrap_or_default();

        let mut combined_prefix = Vec::with_capacity(
            self.module_name.len() + DOMAIN_SEPARATOR.len() + storage_name_len,
            // self.module_path.len()
            //     + self.module_name.len()
            //     + 2 * DOMAIN_SEPARATOR.len()
            //     + storage_name_len,
        );

        // We ignore `self.module_path/` because is common prefix for all keys
        //
        // combined_prefix.extend(self.module_path.as_bytes());
        // combined_prefix.extend(DOMAIN_SEPARATOR);
        combined_prefix.extend(self.module_name.as_bytes());
        combined_prefix.extend(DOMAIN_SEPARATOR);
        if let Some(storage_name) = self.storage_name {
            combined_prefix.extend(storage_name.as_bytes());
            combined_prefix.extend(DOMAIN_SEPARATOR);
        }
        combined_prefix
    }

    /// Returns the hash of the combined prefix.
    pub fn hash<C: Context>(&self) -> [u8; 32] {
        let combined_prefix = self.combine_prefix();
        let mut hasher = C::Hasher::new();
        hasher.update(combined_prefix);
        hasher.finalize().into()
    }
}

impl From<ModulePrefix> for Prefix {
    fn from(prefix: ModulePrefix) -> Self {
        let combined_prefix = prefix.combine_prefix();
        Prefix::new(combined_prefix)
    }
}
