use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, CountedBufReader};
use sov_rollup_interface::Buf;

use super::address::AddressWrapper;

// BlobBuf is a wrapper around Vec<u8> to implement Buf
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlobBuf {
    pub data: Vec<u8>,

    pub offset: usize,
}

// BlobWithSender is a wrapper around BlobBuf to implement BlobReaderTrait
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlobWithSender {
    pub hash: [u8; 32],

    pub sender: AddressWrapper,

    pub blob: CountedBufReader<BlobBuf>,

    pub wtxid: Option<[u8; 32]>,
}

impl BlobWithSender {
    pub fn new(blob: Vec<u8>, sender: Vec<u8>, hash: [u8; 32], wtxid: Option<[u8; 32]>) -> Self {
        Self {
            blob: CountedBufReader::new(BlobBuf {
                data: blob,
                offset: 0,
            }),
            sender: AddressWrapper(sender),
            hash,
            wtxid,
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

impl BlobReaderTrait for BlobWithSender {
    type Address = AddressWrapper;

    fn sender(&self) -> Self::Address {
        self.sender.clone()
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }

    fn wtxid(&self) -> Option<[u8; 32]> {
        self.wtxid
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

    fn serialize_v1(&self) -> borsh::io::Result<Vec<u8>> {
        let v1 = BlobWithSenderV1 {
            hash: self.hash,
            sender: self.sender.clone(),
            blob: &self.blob,
        };
        borsh::to_vec(&v1)
    }
}

#[derive(BorshSerialize)]
/// Internal type to ease serialization process
struct BlobWithSenderV1<'a> {
    hash: [u8; 32],
    sender: AddressWrapper,
    blob: &'a CountedBufReader<BlobBuf>,
}
