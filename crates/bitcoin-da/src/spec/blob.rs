//! Provides an implementation of the BlobReaderTrait for Bitcoin.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlobReaderTrait;

use super::address::AddressWrapper;

/// BlobWithSender is a wrapper around BlobBuf to implement BlobReaderTrait
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlobWithSender {
    pub(crate) hash: [u8; 32],
    pub(crate) sender: AddressWrapper,
    pub(crate) blob: Vec<u8>,
    pub(crate) wtxid: [u8; 32],
}

impl BlobWithSender {
    /// Creates a new BlobWithSender.
    pub fn new(blob: Vec<u8>, sender: Vec<u8>, hash: [u8; 32], wtxid: [u8; 32]) -> Self {
        Self {
            blob,
            sender: AddressWrapper(sender),
            hash,
            wtxid,
        }
    }
}

impl BlobReaderTrait for BlobWithSender {
    type Address = AddressWrapper;

    fn sender(&self) -> Self::Address {
        self.sender.clone()
    }

    fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }

    /// Now that we parse and create BlobWithSender inside the guest code
    /// we can just return the blob as is
    fn full_data(&self) -> &[u8] {
        &self.blob
    }
}
