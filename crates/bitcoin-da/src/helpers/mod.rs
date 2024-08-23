use core::num::NonZeroU16;

use sha2::{Digest, Sha256};

#[cfg(feature = "native")]
pub mod builders;
pub mod compression;
pub mod merkle_tree;
pub mod parsers;
#[cfg(test)]
pub mod test_utils;

/// Header - represents a header of a LightClient transaction
struct TransactionHeaderLightClient<'a> {
    pub(crate) rollup_name: &'a [u8],
    pub(crate) kind: TransactionKindLightClient,
}

impl<'a> TransactionHeaderLightClient<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        let kind = match self.kind {
            TransactionKindLightClient::Complete => 0u16.to_le_bytes(),
            TransactionKindLightClient::Chunked => 1u16.to_le_bytes(),
            TransactionKindLightClient::ChunkedPart => 2u16.to_le_bytes(),
            TransactionKindLightClient::Unknown(v) => v.get().to_le_bytes(),
        };
        let mut result = vec![];
        result.extend_from_slice(&kind);
        result.extend_from_slice(self.rollup_name);
        result
    }
    fn from_bytes<'b: 'a>(bytes: &'b [u8]) -> Option<TransactionHeaderLightClient<'a>>
    where
        'a: 'b,
    {
        let (kind_slice, rollup_name) = bytes.split_at(2);
        if kind_slice.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(kind_slice);
        let kind = match u16::from_le_bytes(kind_bytes) {
            0 => TransactionKindLightClient::Complete,
            1 => TransactionKindLightClient::Chunked,
            2 => TransactionKindLightClient::ChunkedPart,
            n => TransactionKindLightClient::Unknown(NonZeroU16::new(n).expect("Is not zero")),
        };
        Some(Self { rollup_name, kind })
    }
}

/// Header - represents a header of a BatchProof transaction
struct TransactionHeaderBatchProof<'a> {
    pub(crate) rollup_name: &'a [u8],
    pub(crate) kind: TransactionKindBatchProof,
}

impl<'a> TransactionHeaderBatchProof<'a> {
    fn to_bytes(&self) -> Vec<u8> {
        let kind = match self.kind {
            TransactionKindBatchProof::SequencerCommitment => 0u16.to_le_bytes(),
            // TransactionKindBatchProof::ForcedTransaction => 1u16.to_le_bytes(),
            TransactionKindBatchProof::Unknown(v) => v.get().to_le_bytes(),
        };
        let mut result = vec![];
        result.extend_from_slice(&kind);
        result.extend_from_slice(self.rollup_name);
        result
    }
    fn from_bytes<'b: 'a>(bytes: &'b [u8]) -> Option<TransactionHeaderBatchProof<'a>>
    where
        'a: 'b,
    {
        let (kind_slice, rollup_name) = bytes.split_at(2);
        if kind_slice.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(kind_slice);
        let kind = match u16::from_le_bytes(kind_bytes) {
            0 => TransactionKindBatchProof::SequencerCommitment,
            // 1 => TransactionKindBatchProof::ForcedTransaction,
            n => TransactionKindBatchProof::Unknown(NonZeroU16::new(n).expect("Is not zero")),
        };
        Some(Self { rollup_name, kind })
    }
}

/// Type represents a typed enum for LightClient kind
#[repr(u16)]
enum TransactionKindLightClient {
    /// This type of transaction includes full body (< 400kb)
    Complete = 0,
    /// This type of transaction includes txids of chunks (>= 400kb)
    Chunked = 1,
    /// This type of transaction includes chunk parts of body (>= 400kb)
    ChunkedPart = 2,
    Unknown(NonZeroU16),
}

/// Type represents a typed enum for BatchProof kind
#[repr(u16)]
enum TransactionKindBatchProof {
    /// SequencerCommitment
    SequencerCommitment = 0,
    // /// ForcedTransaction
    // ForcedTransaction = 1,
    Unknown(NonZeroU16),
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}
