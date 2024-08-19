//! Defines the traits that must be implemented by zkVMs. A zkVM like Risc0 consists of two components,
//! a "guest" and a "host". The guest is the zkVM program itself, and the host is the physical machine on
//! which the zkVM is running. Both the guest and the host are required to implement the [`Zkvm`] trait, in
//! addition to the specialized [`ZkvmGuest`] and [`ZkvmHost`] trait which is appropriate to that environment.
//!
//! For a detailed example showing how to implement these traits, see the
//! [risc0 adapter](https://github.com/Sovereign-Labs/sovereign-sdk/tree/main/adapters/risc0)
//! maintained by the Sovereign Labs team.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::convert::Into;
use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use digest::Digest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::da::DaSpec;
use crate::soft_confirmation::SignedSoftConfirmationBatch;
use crate::spec::SpecId;

/// The ZK proof generated by the [`ZkvmHost::run`] method.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Proof {
    /// Only public input was generated.
    PublicInput(Vec<u8>),
    /// The serialized ZK proof.
    Full(Vec<u8>),
}

/// A trait implemented by the prover ("host") of a zkVM program.
pub trait ZkvmHost: Zkvm + Clone {
    /// The associated guest type
    type Guest: ZkvmGuest;
    /// Give the guest a piece of advice non-deterministically
    fn add_hint<T: BorshSerialize>(&mut self, item: T);

    /// Simulate running the guest using the provided hints.
    ///
    /// Provides a simulated version of the guest which can be
    /// accessed in the current process.
    fn simulate_with_hints(&mut self) -> Self::Guest;

    /// Run the guest in the true zk environment using the provided hints.
    ///
    /// This runs the guest binary compiled for the zkVM target, optionally
    /// creating a SNARK of correct execution. Running the true guest binary comes
    /// with some mild performance overhead and is not as easy to debug as [`simulate_with_hints`](ZkvmHost::simulate_with_hints).
    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error>;

    /// Extracts public input and receipt from the proof.
    #[allow(clippy::type_complexity)]
    fn extract_output<Da: DaSpec, Root: BorshDeserialize>(
        proof: &Proof,
    ) -> Result<StateTransition<Da, Root>, Self::Error>;

    /// Host recovers pending proving sessions and returns proving results
    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error>;
}

/// A Zk proof system capable of proving and verifying arbitrary Rust code
/// Must support recursive proofs.
pub trait Zkvm: Send + Sync {
    /// A commitment to the zkVM program which is being proven
    type CodeCommitment: Clone + Debug + Serialize + DeserializeOwned;

    /// The error type which is returned when a proof fails to verify
    type Error: Debug;

    /// Interpret a sequence of a bytes as a proof and attempt to verify it against the code commitment.
    /// If the proof is valid, return a reference to the public outputs of the proof.
    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Same as [`verify`](Zkvm::verify), except that instead of returning the output
    /// as a serialized array, it returns a state transition structure.
    /// TODO: specify a deserializer for the output
    fn verify_and_extract_output<Da: DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<StateTransition<Da, Root>, Self::Error>;
}

/// A trait which is accessible from within a zkVM program.
pub trait ZkvmGuest: Zkvm + Send + Sync {
    /// Obtain "advice" non-deterministically from the host
    fn read_from_host<T: BorshDeserialize>(&self) -> T;
    /// Add a public output to the zkVM proof
    fn commit<T: BorshSerialize>(&self, item: &T);
}

/// This trait is implemented on the struct/enum which expresses the validity condition
pub trait ValidityCondition:
    Serialize
    + DeserializeOwned
    + BorshDeserialize
    + BorshSerialize
    + Debug
    + Clone
    + Copy
    + PartialEq
    + Send
    + Sync
    + Eq
{
    /// The error type returned when two [`ValidityCondition`]s cannot be combined.
    type Error: Into<anyhow::Error>;
    /// Combine two conditions into one (typically run inside a recursive proof).
    /// Returns an error if the two conditions cannot be combined
    fn combine<H: Digest>(&self, rhs: Self) -> Result<Self, Self::Error>;
}

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// The public output of a SNARK proof in Sovereign, this struct makes a claim that
/// the state of the rollup has transitioned from `initial_state_root` to `final_state_root`
/// if and only if the condition `validity_condition` is satisfied.
///
/// The period of time covered by a state transition proof may be a single slot, or a range of slots on the DA layer.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct StateTransition<Da: DaSpec, Root> {
    /// The state of the rollup before the transition
    pub initial_state_root: Root,
    /// The state of the rollup after the transition
    pub final_state_root: Root,
    /// The hash before the state transition
    pub initial_batch_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    pub da_slot_hash: Da::SlotHash,
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    pub sequencer_da_public_key: Vec<u8>,
    /// An additional validity condition for the state transition which needs
    /// to be checked outside of the zkVM circuit. This typically corresponds to
    /// some claim about the DA layer history, such as (X) is a valid block on the DA layer
    pub validity_condition: Da::ValidityCondition,
    /// The final spec id after state transition is completed.
    pub final_spec_id: SpecId,
}

/// This trait expresses that a type can check a validity condition.
pub trait ValidityConditionChecker<Condition: ValidityCondition>:
    BorshDeserialize + BorshSerialize + Debug
{
    /// The error type returned when a [`ValidityCondition`] is invalid.
    type Error: Into<anyhow::Error>;
    /// Check a validity condition
    fn check(&mut self, condition: &Condition) -> Result<(), Self::Error>;
}

/// A trait expressing that two items of a type are (potentially fuzzy) matches.
/// We need a custom trait instead of relying on [`PartialEq`] because we allow fuzzy matches.
pub trait Matches<T> {
    /// Check if two items are a match
    fn matches(&self, other: &T) -> bool;
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
#[serde(bound = "StateRoot: Serialize + DeserializeOwned, Witness: Serialize + DeserializeOwned")]
/// Data required to verify a state transition.
pub struct StateTransitionData<StateRoot, Witness, Da: DaSpec> {
    /// The state root before the state transition
    pub initial_state_root: StateRoot,
    /// The state root after the state transition
    pub final_state_root: StateRoot,
    /// The hash before the state transition
    pub initial_batch_hash: [u8; 32],
    /// The `crate::da::DaData` that are being processed as blobs. Everything that's not `crate::da::DaData::SequencerCommitment` will be ignored.
    pub da_data: Vec<Da::BlobTransaction>,
    /// DA block header that the sequencer commitments were found in.
    pub da_block_header_of_commitments: Da::BlockHeader,
    /// The inclusion proof for all DA data.
    pub inclusion_proof: Da::InclusionMultiProof,
    /// The completeness proof for all DA data.
    pub completeness_proof: Da::CompletenessProof,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
    /// The soft confirmations that are inside the sequencer commitments.
    pub soft_confirmations: VecDeque<Vec<SignedSoftConfirmationBatch>>,
    /// Corresponding witness for the soft confirmations.
    pub state_transition_witnesses: VecDeque<Vec<Witness>>,
    /// DA block headers the soft confirmations was constructed on.
    pub da_block_headers_of_soft_confirmations: VecDeque<Vec<Da::BlockHeader>>,
    /// Sequencer soft confirmation public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public_key: Vec<u8>,
    pub sequencer_da_public_key: Vec<u8>,
    /// The range of sequencer commitments that are being processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
}
