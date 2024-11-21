//! This module is the core of the Sovereign SDK. It defines the traits and types that
//! allow the SDK to run the "business logic" of any application generically.
//!
//! The most important trait in this module is the [`StateTransitionFunction`], which defines the
//! main event loop of the rollup.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::da::DaSpec;
use crate::soft_confirmation::SignedSoftConfirmation;
use crate::spec::SpecId;
use crate::zk::CumulativeStateDiff;

#[cfg(any(all(test, feature = "sha2"), feature = "fuzzing"))]
pub mod fuzzing;

/// The configuration of a full node of the rollup which creates zk proofs.
pub struct ProverConfig;
/// The configuration used to initialize the "Verifier" of the state transition function
/// which runs inside of the zkVM.
pub struct ZkConfig;
/// The configuration of a standard full node of the rollup which does not create zk proofs
pub struct StandardConfig;

/// A special marker trait which allows us to define different rollup configurations. There are
/// only 3 possible instantiations of this trait: [`ProverConfig`], [`ZkConfig`], and [`StandardConfig`].
pub trait StateTransitionConfig: sealed::Sealed {}
impl StateTransitionConfig for ProverConfig {}
impl StateTransitionConfig for ZkConfig {}
impl StateTransitionConfig for StandardConfig {}

// https://rust-lang.github.io/api-guidelines/future-proofing.html
mod sealed {
    use super::{ProverConfig, StandardConfig, ZkConfig};

    pub trait Sealed {}
    impl Sealed for ProverConfig {}
    impl Sealed for ZkConfig {}
    impl Sealed for StandardConfig {}
}

/// A receipt for a single transaction. These receipts are stored in the rollup's database
/// and may be queried via RPC. Receipts are generic over a type `R` which the rollup can use to
/// store additional data, such as the status code of the transaction or the amount of gas used.s
#[derive(Debug, Clone, Serialize, Deserialize)]
/// A receipt showing the result of a transaction
pub struct TransactionReceipt<R> {
    /// The canonical hash of this transaction
    pub tx_hash: [u8; 32],
    /// The events output by this transaction
    pub events: Vec<Event>,
    /// Any additional structured data to be saved in the database and served over RPC
    /// For example, this might contain a status code.
    pub receipt: R,
}

/// A receipt for a batch of transactions. These receipts are stored in the rollup's database
/// and may be queried via RPC. Batch receipts are generic over a type `BatchReceiptContents` which the rollup
/// can use to store arbitrary typed data, like the gas used by the batch. They are also generic over a type `TxReceiptContents`,
/// since they contain a vectors of [`TransactionReceipt`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// A receipt giving the outcome of a batch of transactions
pub struct BatchReceipt<BatchReceiptContents, TxReceiptContents> {
    /// The canonical hash of this batch
    pub hash: [u8; 32],
    /// The canonical hash of previous batch
    pub prev_hash: [u8; 32],
    /// The receipts of all the transactions in this batch.
    pub tx_receipts: Vec<TransactionReceipt<TxReceiptContents>>,
    /// Any additional structured data to be saved in the database and served over RPC
    pub phantom_data: PhantomData<BatchReceiptContents>,
}

/// The output of the function that applies sequencer commitments to the state in the verifier
pub struct ApplySequencerCommitmentsOutput<StateRoot> {
    /// Final state root after all sequencer commitments were applied
    pub final_state_root: StateRoot,
    /// State diff generated after applying
    pub state_diff: CumulativeStateDiff,
    /// Last processed L2 block height
    pub last_l2_height: u64,
}

/// A receipt for a soft confirmation of transactions. These receipts are stored in the rollup's database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftConfirmationReceipt<T, DS: DaSpec> {
    /// L2 block height
    pub l2_height: u64,
    /// DA layer block number
    pub da_slot_height: u64,
    /// DA layer block hash
    pub da_slot_hash: <DS as DaSpec>::SlotHash,
    /// DA layer transactions commitment
    pub da_slot_txs_commitment: <DS as DaSpec>::SlotHash,
    /// The canonical hash of this batch
    pub hash: [u8; 32],
    /// The canonical hash of the previous batch
    pub prev_hash: [u8; 32],
    /// The receipts of all the transactions in this batch.
    pub tx_receipts: Vec<TransactionReceipt<T>>,
    /// Soft confirmation signature computed from borsh serialization of da_slot_height, da_slot_hash, pre_state_root, txs
    pub soft_confirmation_signature: Vec<u8>,
    /// Sequencer public key
    pub pub_key: Vec<u8>,
    /// Deposit data from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// Base layer fee rate sats/wei etc. per byte.
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp
    pub timestamp: u64,
}

/// A diff of the state, represented as a list of key-value pairs.
pub type StateDiff = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// Result of applying a slot to current state
/// Where:
///  - S - generic for state root
///  - B - generic for batch receipt contents
///  - T - generic for transaction receipt contents
///  - W - generic for witness
pub struct SlotResult<S, Cs, B, T, W> {
    /// Final state root after all blobs were applied
    pub state_root: S,
    /// Container for all state alterations that happened during slot execution
    pub change_set: Cs,
    /// Receipt for each applied batch
    pub batch_receipts: Vec<BatchReceipt<B, T>>,
    /// Witness after applying the whole block
    pub witness: W,
    /// State diff
    pub state_diff: StateDiff,
}

/// Helper struct which contains initial and final state roots.
pub struct StateRootTransition<Root> {
    /// Initial state root
    pub init_root: Root,
    /// Final state root
    pub final_root: Root,
}

/// Result of applying a soft confirmation to current state
/// Where:
/// - S - generic for state root
/// - Cs - generic for change set
/// - T - generic for transaction receipt contents
/// - W - generic for witness
/// - Da - generic for DA layer
pub struct SoftConfirmationResult<S, Cs, T, W, Da: DaSpec> {
    /// Contains state root before and after applying txs
    pub state_root_transition: StateRootTransition<S>,
    /// Container for all state alterations that happened during soft confirmation execution
    pub change_set: Cs,
    /// Witness after applying the whole block
    pub witness: W,
    /// Witness after applying the whole block
    pub offchain_witness: W,
    /// State diff after applying the whole block
    pub state_diff: StateDiff,
    /// soft confirmation receipt
    /// This is the receipt that is stored in the database
    pub soft_confirmation_receipt: SoftConfirmationReceipt<T, Da>,
}

/// Transaction should provide its hash in order to put Receipt by hash.
pub trait TransactionDigest {
    /// Compute digest for the whole Transaction struct
    fn compute_digest<D: digest::Digest>(&self) -> digest::Output<D>;
}

// TODO(@preston-evans98): update spec with simplified API
/// State transition function defines business logic that responsible for changing state.
/// Terminology:
///  - state root: root hash of state merkle tree
///  - block: DA layer block
///  - batch: Set of transactions grouped together, or block on L2
///  - blob: Non serialised batch or anything else that can be posted on DA layer, like attestation or proof.
pub trait StateTransitionFunction<Da: DaSpec> {
    /// The type of rollup transaction
    type Transaction: TransactionDigest
        + Clone
        + BorshDeserialize
        + BorshSerialize
        + Send
        + Sync
        + 'static;
    /// Root hash of state merkle tree
    type StateRoot: BorshDeserialize
        + BorshSerialize
        + Serialize
        + DeserializeOwned
        + Clone
        + AsRef<[u8]>
        + Debug
        + Sync
        + Send
        + 'static;

    /// The initial params of the rollup.
    type GenesisParams;

    /// State of the rollup before transition.
    type PreState;

    /// State of the rollup after transition.
    type ChangeSet;

    /// The contents of a transaction receipt. This is the data that is persisted in the database
    type TxReceiptContents: Serialize + DeserializeOwned + Clone;

    /// The contents of a batch receipt. This is the data that is persisted in the database
    type BatchReceiptContents: Serialize + DeserializeOwned + Clone;

    /// Witness is a data that is produced during actual batch execution
    /// or validated together with proof during verification
    type Witness: Default
        + BorshSerialize
        + BorshDeserialize
        + Serialize
        + DeserializeOwned
        + Send
        + Sync
        + 'static;

    /// Perform one-time initialization for the genesis block and
    /// returns the resulting root hash and changeset.
    /// If the init chain fails we panic.
    fn init_chain(
        &self,
        genesis_state: Self::PreState,
        params: Self::GenesisParams,
    ) -> (Self::StateRoot, Self::ChangeSet);

    /// Called at each **DA-layer block** - whether or not that block contains any
    /// data relevant to the rollup.
    /// If slot is started in Full Node mode, default witness should be provided.
    /// If slot is started in Zero Knowledge mode, witness from execution should be provided.
    ///
    /// Applies batches of transactions to the rollup,
    /// slashing the sequencer who proposed the blob on failure.
    /// The blobs are contained into a slot whose data is contained within the `slot_data` parameter,
    /// this parameter is mainly used within the begin_slot hook.
    /// The concrete blob type is defined by the DA layer implementation,
    /// which is why we use a generic here instead of an associated type.
    ///
    /// Commits state changes to the database
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn apply_slot<'a, I>(
        &self,
        current_spec: SpecId,
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        witness: Self::Witness,
        slot_header: &Da::BlockHeader,
        blobs: I,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    >
    where
        I: IntoIterator<Item = &'a mut Da::BlobTransaction>;

    /// Called at each **Soft confirmation block**
    /// If slot is started in Full Node mode, default witness should be provided.
    /// If slot is started in Zero Knowledge mode, witness from execution should be provided.
    ///
    /// Checks for soft confirmation signature, data correctness (pre state root is correct etc.) and applies batches of transactions to the rollup,
    /// The blobs are contained into a slot whose data is contained within the `slot_data` parameter,
    /// this parameter is mainly used within the begin_slot hook.
    /// The concrete blob type is defined by the DA layer implementation,
    /// which is why we use a generic here instead of an associated type.
    ///
    /// Commits state changes to the database
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn apply_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &[u8],
        pre_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        state_witness: Self::Witness,
        offchain_witness: Self::Witness,
        slot_header: &Da::BlockHeader,
        soft_confirmation: &mut SignedSoftConfirmation<Self::Transaction>,
    ) -> Result<
        SoftConfirmationResult<
            Self::StateRoot,
            Self::ChangeSet,
            Self::TxReceiptContents,
            Self::Witness,
            Da,
        >,
        SoftConfirmationError,
    >;

    /// Runs a vector of Soft Confirmations
    /// Used for proving the L2 block state transitions
    // TODO: don't use tuple as return type.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        sequencer_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        initial_state_root: &Self::StateRoot,
        pre_state: Self::PreState,
        da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        sequencer_commitments_range: (u32, u32),
        witnesses: VecDeque<Vec<(Self::Witness, Self::Witness)>>,
        slot_headers: VecDeque<Vec<Da::BlockHeader>>,
        soft_confirmations: VecDeque<Vec<SignedSoftConfirmation<Self::Transaction>>>,
        preproven_commitment_indicies: Vec<usize>,
    ) -> ApplySequencerCommitmentsOutput<Self::StateRoot>;
}

#[derive(Debug)]
/// Error that can occur during appyling a soft confirmation
pub enum SoftConfirmationError {
    /// The public key of the sequencer (known by a full node or prover) does not match
    /// the public key in the soft confirmation
    SequencerPublicKeyMismatch,
    /// The DA hash in the soft confirmation does not match the hash of the DA block provided
    InvalidDaHash,
    /// The DA tx commitment in the soft confirmation does not match the tx commitment of the DA block provided
    InvalidDaTxsCommitment,
    /// The hash of the soft confirmation is incorrect
    InvalidSoftConfirmationHash,
    /// The soft confirmation signature is incorret
    InvalidSoftConfirmationSignature,
    /// Any other error that can occur during the application of a soft confirmation
    /// These can come from runtime hooks etc.
    Other(String),
}

#[cfg(feature = "native")]
impl std::error::Error for SoftConfirmationError {}

#[cfg(feature = "native")]
impl std::fmt::Display for SoftConfirmationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoftConfirmationError::SequencerPublicKeyMismatch => {
                write!(f, "Sequencer public key mismatch")
            }
            SoftConfirmationError::InvalidDaHash => write!(f, "Invalid DA hash"),
            SoftConfirmationError::InvalidDaTxsCommitment => write!(f, "Invalid DA txs commitment"),
            SoftConfirmationError::InvalidSoftConfirmationHash => {
                write!(f, "Invalid soft confirmation hash")
            }
            SoftConfirmationError::InvalidSoftConfirmationSignature => {
                write!(f, "Invalid soft confirmation signature")
            }
            SoftConfirmationError::Other(s) => write!(f, "Other error: {}", s),
        }
    }
}

/// A key-value pair representing a change to the rollup state
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub struct Event {
    key: EventKey,
    value: EventValue,
}

impl Event {
    /// Create a new event with the given key and value
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: EventKey(key.as_bytes().to_vec()),
            value: EventValue(value.as_bytes().to_vec()),
        }
    }

    /// Get the event key
    pub fn key(&self) -> &EventKey {
        &self.key
    }

    /// Get the event value
    pub fn value(&self) -> &EventValue {
        &self.value
    }
}

/// The key of an event. This is a wrapper around a `Vec<u8>`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub struct EventKey(Vec<u8>);

impl EventKey {
    /// Return the inner bytes of the event key.
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }
}

/// The value of an event. This is a wrapper around a `Vec<u8>`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(proptest_derive::Arbitrary))]
pub struct EventValue(Vec<u8>);

impl EventValue {
    /// Return the inner bytes of the event value.
    pub fn inner(&self) -> &Vec<u8> {
        &self.0
    }
}
