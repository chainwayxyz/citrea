use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::block::{L2Block, L2Header};
use crate::da::SequencerCommitment;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

type InputV3Part2<Witness> = VecDeque<Vec<(u64, L2Block, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Tangerine elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2(pub InputV3Part2<Witness>);

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the Tangerine elf input
pub struct BatchProofCircuitInputV3Part1 {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The sequencer commitment before the first sequencer commitment in the sequencer_commitments vector
    /// If it is none than this is the first batch proof
    /// Else the index of the sequencer commitment should be `sequencer_commitments[0].index - 1``
    pub previous_sequencer_commitment: Option<SequencerCommitment>,
    /// A proof for the previous sequencer commitment's last header
    /// None if the previous sequencer commitment is None
    pub prev_hash_proof: Option<PrevHashProof>,
    /// Sequencer commitments being proven
    /// Since `SequencerCommitment` does not have the sequencer's signature,
    /// the light client prover will be doing the signature verification
    /// when it is extracting the commitments from L1
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// Short header proofs for verifying system transactions
    pub short_header_proofs: VecDeque<Vec<u8>>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    pub cache_prune_l2_heights: Vec<u64>,
    /// The witness needed to access the last L1 hash on the bitcoin light client contract
    pub last_l1_hash_witness: Witness,
}

#[derive(BorshDeserialize, BorshSerialize)]
/// A merkle proof for the last header in the previous sequencer commitment
/// This is used to verify the first `prev_hash` in the batch proof circuit
/// The `prev_hash` is the hash of the last header in the previous sequencer commitment
pub struct PrevHashProof {
    /// Rightmost header in the L2 block hash merkle tree
    pub last_header: L2Header,
    /// Merkle proof for the last header in the previous sequencer commitment
    pub merkle_proof_bytes: Vec<u8>,
    /// Give the start of the previous sequencer commitment as a hint
    /// so index can be calculated
    pub prev_sequencer_commitment_start: u64,
}
