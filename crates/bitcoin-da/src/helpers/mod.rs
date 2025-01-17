use core::num::NonZeroU16;

use bitcoin::consensus::Encodable;
use bitcoin::Transaction;
use sha2::{Digest, Sha256};

#[cfg(feature = "native")]
pub mod builders;
pub mod merkle_tree;
pub mod parsers;

/// Type represents a typed enum for LightClient kind
#[repr(u16)]
enum TransactionKindLightClient {
    /// This type of transaction includes full body (< 400kb)
    Complete = 0,
    /// This type of transaction includes txids of chunks (>= 400kb)
    Chunked = 1,
    /// This type of transaction includes chunk parts of body (>= 400kb)
    ChunkedPart = 2,
    /// This type of transaction includes a new batch proof method_id
    BatchProofMethodId = 3,
    Unknown(NonZeroU16),
}

impl TransactionKindLightClient {
    #[cfg(feature = "native")]
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionKindLightClient::Complete => 0u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::Chunked => 1u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::ChunkedPart => 2u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::BatchProofMethodId => 3u16.to_le_bytes().to_vec(),
            TransactionKindLightClient::Unknown(v) => v.get().to_le_bytes().to_vec(),
        }
    }
    fn from_bytes(bytes: &[u8]) -> Option<TransactionKindLightClient> {
        if bytes.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(bytes);
        match u16::from_le_bytes(kind_bytes) {
            0 => Some(TransactionKindLightClient::Complete),
            1 => Some(TransactionKindLightClient::Chunked),
            2 => Some(TransactionKindLightClient::ChunkedPart),
            3 => Some(TransactionKindLightClient::BatchProofMethodId),
            n => Some(TransactionKindLightClient::Unknown(
                NonZeroU16::new(n).expect("Is not zero"),
            )),
        }
    }
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

impl TransactionKindBatchProof {
    #[cfg(feature = "native")]
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            TransactionKindBatchProof::SequencerCommitment => 0u16.to_le_bytes().to_vec(),
            // TransactionKindBatchProof::ForcedTransaction => 1u16.to_le_bytes(),
            TransactionKindBatchProof::Unknown(v) => v.get().to_le_bytes().to_vec(),
        }
    }
    fn from_bytes(bytes: &[u8]) -> Option<TransactionKindBatchProof> {
        if bytes.len() != 2 {
            return None;
        }
        let mut kind_bytes = [0; 2];
        kind_bytes.copy_from_slice(bytes);
        match u16::from_le_bytes(kind_bytes) {
            0 => Some(TransactionKindBatchProof::SequencerCommitment),
            // 1 => TransactionKindBatchProof::ForcedTransaction,
            n => Some(TransactionKindBatchProof::Unknown(
                NonZeroU16::new(n).expect("Is not zero"),
            )),
        }
    }
}

pub fn calculate_double_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    let result = hasher.finalize_reset();
    hasher.update(result);
    hasher.finalize().into()
}

pub fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}

/// Computes the [`Txid`].
///
/// Hashes the transaction **excluding** the segwit data (i.e. the marker, flag bytes, and the
/// witness fields themselves). For non-segwit transactions which do not have any segwit data,
/// this will be equal to [`Transaction::compute_wtxid()`].
pub fn calculate_txid(tx: &Transaction) -> [u8; 32] {
    let mut enc = vec![];
    tx.version
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.input
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.output
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    tx.lock_time
        .consensus_encode(&mut enc)
        .expect("engines don't error");
    calculate_double_sha256(&enc)
}

/// Computes the segwit version of the transaction id.
///
/// Hashes the transaction **including** all segwit data (i.e. the marker, flag bytes, and the
/// witness fields themselves). For non-segwit transactions which do not have any segwit data,
/// this will be equal to [`Transaction::txid()`].
pub fn calculate_wtxid(tx: &Transaction) -> [u8; 32] {
    let mut enc = vec![];
    tx.consensus_encode(&mut enc).expect("engines don't error");
    calculate_double_sha256(&enc)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::Transaction;

    use crate::helpers::{calculate_txid, calculate_wtxid};

    #[test]
    fn calculate_txid_wtxid() {
        let hex_tx = "020000000001013a66019bfcc719ba12586a83ebbb0b3debdc945f563cd64fd44c8044e3d3a1790100000000fdffffff028fa2aa060000000017a9147ba15d4e0d8334de3a68cf3687594e2d1ee5b00d879179e0090000000016001493c93ad222e57d65438545e048822ede2d418a3d0247304402202432e6c422b93705fbc57b350ea43e4ef9441c0907988eff051eaac807fc8cf2022046c92b540b5f04f8da11febb5d2a478aed1b8bc088e769da8b78fffcae8c9a9a012103e2991b47d9c788f55379f9ef519b642d79d7dfe0e7555ec5575ee934b2dca1223f5d0c00";

        let tx: Transaction =
            bitcoin::consensus::deserialize(&hex::decode(hex_tx).unwrap()).unwrap();

        assert_eq!(tx.compute_txid().to_byte_array(), calculate_txid(&tx));
        assert_eq!(tx.compute_wtxid().to_byte_array(), calculate_wtxid(&tx));
    }
}
