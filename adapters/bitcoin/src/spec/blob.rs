use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, CountedBufReader};
use sov_rollup_interface::Buf;

use super::address::AddressWrapper;

// BlobBuf is a wrapper around Vec<u8> to implement Buf
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobBuf {
    pub data: Vec<u8>,

    pub offset: usize,
}

impl BlobWithSender {
    pub fn new(blob: Vec<u8>, sender: Vec<u8>, hash: [u8; 32]) -> Self {
        Self {
            blob: CountedBufReader::new(BlobBuf {
                data: blob,
                offset: 0,
            }),
            sender: AddressWrapper(sender),
            hash,
        }
    }
}

impl Buf for BlobBuf {
    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn chunk(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    fn advance(&mut self, cnt: usize) {
        self.offset += cnt;
    }
}

// BlobWithSender is a wrapper around BlobBuf to implement BlobReaderTrait
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobWithSender {
    pub hash: [u8; 32],

    pub sender: AddressWrapper,

    pub blob: CountedBufReader<BlobBuf>,
}

impl BlobReaderTrait for BlobWithSender {
    type Address = AddressWrapper;

    fn sender(&self) -> Self::Address {
        self.sender.clone()
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }

    fn verified_data(&self) -> &[u8] {
        self.blob.accumulator()
    }

    fn total_len(&self) -> usize {
        self.blob.total_len()
    }

    #[cfg(feature = "native")]
    fn advance(&mut self, num_bytes: usize) -> &[u8] {
        self.blob.advance(num_bytes);
        self.verified_data()
    }
}
