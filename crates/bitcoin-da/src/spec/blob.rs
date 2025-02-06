use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, CountedBufReader};
use sov_rollup_interface::Buf;

use super::address::AddressWrapper;

// BlobWithSender is a wrapper around BlobBuf to implement BlobReaderTrait
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlobWithSender {
    pub hash: [u8; 32],

    pub sender: AddressWrapper,

    pub blob: Vec<u8>,

    pub wtxid: Option<[u8; 32]>,
}

impl BlobWithSender {
    pub fn new(blob: Vec<u8>, sender: Vec<u8>, hash: [u8; 32], wtxid: Option<[u8; 32]>) -> Self {
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

    fn hash(&self) -> [u8; 32] {
        self.hash
    }

    fn wtxid(&self) -> Option<[u8; 32]> {
        self.wtxid
    }

    /// Now that we parse and create BlobWithSender inside the guest code
    /// we can just return the blob as is
    fn full_data(&self) -> &[u8] {
        &self.blob
    }

    fn total_len(&self) -> usize {
        self.blob.len()
    }

    fn serialize_v1(&self) -> borsh::io::Result<Vec<u8>> {
        let blob = self.blob.clone();
        let len = blob.len();

        let mut counted_buf = CountedBufReader::new(BlobBuf {
            data: blob,
            offset: 0,
        });
        counted_buf.advance(len);

        let v1 = BlobWithSenderV1 {
            hash: self.hash,
            sender: self.sender.clone(),
            blob: &counted_buf,
        };
        borsh::to_vec(&v1)
    }

    fn serialize_v2(&self) -> borsh::io::Result<Vec<u8>> {
        let blob = self.blob.clone();
        let len = blob.len();

        let mut counted_buf = CountedBufReader::new(BlobBuf {
            data: blob,
            offset: 0,
        });
        counted_buf.advance(len);

        let v2 = BlobWithSenderV2 {
            hash: self.hash,
            sender: self.sender.clone(),
            blob: counted_buf,
            wtxid: self.wtxid,
        };
        borsh::to_vec(&v2)
    }
}

#[derive(BorshSerialize)]
/// Internal type to ease serialization process
struct BlobWithSenderV1<'a> {
    hash: [u8; 32],
    sender: AddressWrapper,
    blob: &'a CountedBufReader<BlobBuf>,
}

#[derive(BorshSerialize)]
pub struct BlobWithSenderV2 {
    pub hash: [u8; 32],

    pub sender: AddressWrapper,

    pub blob: CountedBufReader<BlobBuf>,

    pub wtxid: Option<[u8; 32]>,
}

// BlobBuf is a wrapper around Vec<u8> to implement Buf
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct BlobBuf {
    pub data: Vec<u8>,

    pub offset: usize,
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
