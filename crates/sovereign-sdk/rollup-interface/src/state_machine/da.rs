//! Defines traits and types used by the rollup to verify claims about the
//! DA layer.
use std::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::zk::Proof;
use crate::{BasicAddress, Network};

/// Commitments made to the DA layer from the sequencer.
/// Has merkle root of l2 block hashes from L1 start block to L1 end block (inclusive)
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct SequencerCommitment {
    /// Merkle root of l2 block hashes
    pub merkle_root: [u8; 32],
    /// Absolute order of the sequencer commitment, the first commitment has index 0, the next one has 1...
    pub index: u32,
    /// End L2 block's number
    pub l2_end_block_number: u64,
}

impl SequencerCommitment {
    /// Compute sha256 hash
    pub fn serialize_and_calculate_sha_256(&self) -> [u8; 32] {
        let serialized =
            borsh::to_vec(self).expect("Sequencer commitment serialization cannot fail");
        let mut hasher = Sha256::default();
        hasher.update(&serialized);
        let hash = hasher.finalize();
        hash.into()
    }
}

/// A new batch proof method_id starting to be applied from the l2_block_number (inclusive).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct BatchProofMethodId {
    /// New method id of upcoming fork
    pub method_id: [u32; 8],
    /// Activation L2 height of the new method id
    pub activation_l2_height: u64,
}

/// SequencerCommitment's are ordered by their index
impl core::cmp::PartialOrd for SequencerCommitment {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.index.cmp(&other.index))
    }
}

/// SequencerCommitment's are ordered by their index
impl core::cmp::Ord for SequencerCommitment {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

/// Transaction request to send to the DA queue.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum DaTxRequest {
    /// A commitment from the sequencer
    SequencerCommitment(SequencerCommitment),
    /// Or a zk proof and state diff
    ZKProof(Proof),
    /// Batch proof method id update for light client
    BatchProofMethodId(BatchProofMethodId),
}

/// Data written to DA and read from DA must be the borsh serialization of this enum
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum DataOnDa {
    /// A zk proof and state diff
    Complete(Proof),
    /// A list of tx ids
    Aggregate(Vec<[u8; 32]>, Vec<[u8; 32]>),
    /// A chunk of an aggregate
    Chunk(Vec<u8>),
    /// A new batch proof method_id
    BatchProofMethodId(BatchProofMethodId),
    /// Sequencer commitment
    SequencerCommitment(SequencerCommitment),
}

/// A specification for the types used by a DA layer.
pub trait DaSpec:
    'static + BorshDeserialize + BorshSerialize + Debug + PartialEq + Eq + Clone + Send + Sync
{
    /// The hash of a DA layer block
    type SlotHash: BlockHashTrait;

    /// The block header type used by the DA layer
    type BlockHeader: BlockHeaderTrait<Hash = Self::SlotHash> + Send + Sync;

    /// The transaction type used by the DA layer.
    type BlobTransaction: BlobReaderTrait<Address = Self::Address> + Send + Sync + Clone;

    /// The type used to represent addresses on the DA layer.
    type Address: BasicAddress + Send + Sync;

    /// A proof that each tx in a set of blob transactions is included in a given block.
    type InclusionMultiProof: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + Send
        + Sync;

    /// A proof that a claimed set of transactions is complete.
    /// For example, this could be a range proof demonstrating that
    /// the provided BlobTransactions represent the entire contents
    /// of Celestia namespace in a given block
    type CompletenessProof: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + Send
        + Sync;

    /// The parameters of the rollup which are baked into the state-transition function.
    /// For example, this could include the namespace of the rollup on Celestia.
    type ChainParams: Send + Sync;

    /// A verifiable proof that upon verification, returns the hash of the header,
    /// the transaction commitment from the header, and the txid merkle proof height of the coinbase transaction.
    type ShortHeaderProof: VerifiableShortHeaderProof
        + BorshDeserialize
        + BorshSerialize
        + Send
        + Sync
        + Debug;

    /// Decompress chunks to complete
    fn decompress_chunks(complete_chunks: &[u8]) -> Result<Vec<u8>, DecompressError>;
}

/// Decompression error
pub struct DecompressError;

#[derive(Debug)]
/// Information needed to update L1 light client system contract
pub struct L1UpdateSystemTransactionInfo {
    /// Hash of header at height `block_height`
    pub header_hash: [u8; 32],
    /// Hash of header at height `block_height - 1`
    pub prev_header_hash: [u8; 32],
    /// Transaction commitment of the block
    /// For bitcoin this should be the wtxid commitment
    pub tx_commitment: [u8; 32],
    /// Number of hashes needed for the merkle inclusion proof of the coinbase transaction
    pub coinbase_txid_merkle_proof_height: u8,
    /// Block height
    pub block_height: u64,
}
/// A trait for a verifiable short header proof
pub trait VerifiableShortHeaderProof {
    /// Verifies the proof and returns the header hash, transaction commitment and coinbase transaction txid merkle proof
    /// height.
    ///
    /// The proof only shows that for a claimed header hash, wtxid merkle root and coinbase txid merkle proof height,
    /// are valid.
    ///
    /// These proofs will be used inside the batch proofs, and the hash is going to be committed to the output of the
    /// proof. It will be up to the verifier to check if the hash is correct.
    ///
    /// In the light client proof, the circuit will extract the `l1_hashes` output and will check that the hashes are
    /// included in the header chain.
    fn verify(&self) -> Result<L1UpdateSystemTransactionInfo, ShortHeaderProofVerificationError>;
}

#[derive(Debug, PartialEq, Eq)]
/// Error that can arise from short form header proof
pub enum ShortHeaderProofVerificationError {
    /// Wrong coinbase was supplied
    InvalidCoinbaseMerkleProof,
    /// Tx commitment in `DaSpec::BlockHeader` was wrong
    WrongTxCommitment {
        /// The expected commitment
        expected: [u8; 32],
        /// The actual commitment
        actual: [u8; 32],
    },
    /// Provided precomputed hash was incorrect
    InvalidHeaderHash,
}

/// Latest da state to verify and apply da block changes
#[derive(Default, Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq)]
pub struct LatestDaState {
    /// Proved DA block's header hash
    /// This is used to compare the previous DA block hash with first batch proof's DA block hash
    pub block_hash: [u8; 32],
    /// Height of the blockchain
    pub block_height: u64,
    /// Total work done in the DA blockchain
    pub total_work: [u8; 32],
    /// Current target bits of the DA block
    pub current_target_bits: u32,
    /// The time of the first block in the current epoch (the difficulty adjustment timestamp)
    pub epoch_start_time: u32,
    /// The UNIX timestamps in seconds of the previous 11 blocks
    pub prev_11_timestamps: [u32; 11],
}

/// A `DaVerifier` implements the logic required to create a zk proof that some data
/// has been processed.
///
/// This trait implements the required functionality to *verify* claims of the form
/// "If X is the most recent block in the DA layer, then Y is the ordered set of transactions that must
/// be processed by the rollup."
pub trait DaVerifier: Send + Sync {
    /// The set of types required by the DA layer.
    type Spec: DaSpec;

    /// The error type returned by the DA layer's verification function
    /// TODO: Should we add `std::Error` bound so it can be `()?` ?
    type Error: Debug;

    /// Create a new da verifier with the given chain parameters
    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self;

    /// Extract the relevant transactions from a block, using provided proofs to verify the data.
    fn verify_transactions(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
    ) -> Result<Vec<<Self::Spec as DaSpec>::BlobTransaction>, Self::Error>;

    /// Verify that the block header is valid for the given previous light client proof output
    fn verify_header_chain(
        &self,
        latest_da_state: Option<&LatestDaState>,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        network: Network,
    ) -> Result<LatestDaState, Self::Error>;

    /// Decompress chunks to complete
    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize, PartialEq)]
/// Simple structure that implements the Read trait for a buffer and  counts the number of bytes read from the beginning.
/// Useful for the partial blob reading optimization: we know for each blob how many bytes have been read from the beginning.
///
/// Because of soundness issues we cannot implement the Buf trait because the prover could get unproved blob data using the chunk method.
pub struct CountedBufReader<B: bytes::Buf> {
    /// The original blob data.
    inner: B,

    /// An accumulator that stores the data read from the blob buffer into a vector.
    /// Allows easy access to the data that has already been read
    accumulator: Vec<u8>,
}

impl<B: bytes::Buf> CountedBufReader<B> {
    /// Creates a new buffer reader with counter from an object that implements the buffer trait
    pub fn new(inner: B) -> Self {
        let buf_size = inner.remaining();
        CountedBufReader {
            inner,
            accumulator: Vec::with_capacity(buf_size),
        }
    }

    /// Advance the accumulator by `num_bytes` bytes. If `num_bytes` is greater than the length
    /// of remaining unverified data, then all remaining unverified data is added to the accumulator.
    pub fn advance(&mut self, num_bytes: usize) {
        let requested = num_bytes;
        let remaining = self.inner.remaining();
        if remaining == 0 {
            return;
        }
        // `Buf::advance` would panic if `num_bytes` was greater than the length of the remaining unverified data,
        // but we just advance to the end of the buffer.
        let num_to_read = core::cmp::min(remaining, requested);
        // Extend the inner vector with zeros (copy_to_slice requires the vector to have
        // the correct *length* not just capacity)
        self.accumulator
            .resize(self.accumulator.len() + num_to_read, 0);

        // Use copy_to_slice to overwrite the zeros we just added
        let accumulator_len = self.accumulator.len();
        self.inner
            .copy_to_slice(self.accumulator[accumulator_len - num_to_read..].as_mut());
    }

    /// Getter: returns a reference to an accumulator of the blob data read by the rollup
    pub fn accumulator(&self) -> &[u8] {
        &self.accumulator
    }

    /// Contains the total length of the data (length already read + length remaining)
    pub fn total_len(&self) -> usize {
        self.inner.remaining() + self.accumulator.len()
    }
}

/// This trait wraps "blob transaction" from a data availability layer allowing partial consumption of the
/// blob data by the rollup.
///
/// The motivation for this trait is limit the amount of validation work that a rollup has to perform when
/// verifying a state transition. In general, it will often be the case that a rollup only cares about some
/// portion of the data from a blob. For example, if a blob contains a malformed transaction then the rollup
/// will slash the sequencer and exit early - so it only cares about the content of the blob up to that point.
///
/// This trait allows the DaVerifier to track which data was read by the rollup, and only verify the relevant data.
pub trait BlobReaderTrait:
    BorshDeserialize + BorshSerialize + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// The type used to represent addresses on the DA layer.
    type Address: BasicAddress;

    /// Returns the address (on the DA layer) of the entity which submitted the blob transaction
    fn sender(&self) -> Self::Address;

    /// Returns the witness transaction ID of the blob as it appears on the DA layer
    fn wtxid(&self) -> [u8; 32];

    /// Returns the full data of the blob
    fn full_data(&self) -> &[u8];
}

/// Trait with collection of trait bounds for a block hash.
pub trait BlockHashTrait:
    // so it is compatible with StorageManager implementation?
    BorshDeserialize + BorshSerialize + Serialize + DeserializeOwned + PartialEq + Debug + Send + Sync + Clone + Eq + From<[u8; 32]> + Into<[u8; 32]> + core::hash::Hash
{
}

/// A block header, typically used in the context of an underlying DA blockchain.
pub trait BlockHeaderTrait:
    PartialEq + Debug + Clone + BorshSerialize + BorshDeserialize + Serialize + DeserializeOwned
{
    /// Each block header must have a unique canonical hash.
    type Hash: Clone + core::fmt::Display + Into<[u8; 32]>;

    /// Each block header must contain the hash of the previous block.
    fn prev_hash(&self) -> Self::Hash;

    /// Hash the type to get the digest.
    /// This is pre computed so can't be trusted in zk
    /// until `verify_hash` is called
    fn hash(&self) -> Self::Hash;

    /// Verify the hash of the block.
    fn verify_hash(&self) -> bool;

    /// Transactions commitment of the block.
    fn txs_commitment(&self) -> Self::Hash;

    /// The current header height
    fn height(&self) -> u64;

    /// The timestamp of the block
    fn time(&self) -> Time;

    /// The bits of the block
    fn bits(&self) -> u32;

    /// Coinbase txid merkle proof height in the block.
    fn coinbase_txid_merkle_proof_height(&self) -> u64;
}

#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Default,
)]
/// A timestamp, represented as seconds since the unix epoch.
pub struct Time {
    /// The number of seconds since the unix epoch
    secs: i64,
    nanos: u32,
}

#[derive(Debug)]
#[cfg_attr(
    feature = "native",
    derive(thiserror::Error),
    error("Only intervals less than one second may be represented as nanoseconds")
)]
/// An error that occurs when trying to create a `NanoSeconds` representing more than one second
pub struct ErrTooManyNanos;

/// A number of nanoseconds
pub struct NanoSeconds(u32);

impl NanoSeconds {
    /// Try to turn a u32 into a `NanoSeconds`. Only values less than one second are valid.
    pub fn new(nanos: u32) -> Result<Self, ErrTooManyNanos> {
        if nanos < NANOS_PER_SECOND {
            Ok(NanoSeconds(nanos))
        } else {
            Err(ErrTooManyNanos)
        }
    }
}

const NANOS_PER_SECOND: u32 = 1_000_000_000;

impl Time {
    /// The time since the unix epoch
    pub const fn new(secs: i64, nanos: NanoSeconds) -> Self {
        Time {
            secs,
            nanos: nanos.0,
        }
    }

    /// Get the current time
    pub fn now() -> Self {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        Time {
            secs: current_time.as_secs() as i64,
            nanos: current_time.subsec_nanos(),
        }
    }

    /// Create a time from the specified number of whole seconds.
    pub const fn from_secs(secs: i64) -> Self {
        Time { secs, nanos: 0 }
    }

    /// Returns the number of whole seconds since the epoch
    ///
    /// The returned value does not include the fractional (nanosecond) part of the duration,
    /// which can be obtained using `subsec_nanos`.
    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// Returns the fractional part of this [`Time`], in nanoseconds.
    ///
    /// This method does not return the length of the time when represented by nanoseconds.
    /// The returned number always represents a fractional portion of a second (i.e., it is less than one billion).
    pub fn subsec_nanos(&self) -> u32 {
        self.nanos
    }
}
