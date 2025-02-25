use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::da::{DaSpec, SequencerCommitment};
use crate::soft_confirmation::L2Block;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

type InputV3Part2<'txs, Tx, Witness> = VecDeque<Vec<(u64, L2Block<'txs, Tx>, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Fork2 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2<'txs, Tx: Clone + BorshSerialize>(
    pub InputV3Part2<'txs, Tx, Witness>,
);

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the Kumquat elf input
pub struct BatchProofCircuitInputV3Part1<Da: DaSpec> {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// Sequencer commitments being proven
    /// Since `SequencerCommitment` does not have the sequencer's signature,
    /// the light client prover will be doing the signature verification
    /// when it is extracting the commitments from L1
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// DA block headers the soft confirmations was constructed on.
    /// TODO: this is going to be replaced with erce's pr most probably
    pub da_block_headers_of_soft_confirmations: VecDeque<Vec<Da::BlockHeader>>,
    /// Short header proofs for verifying system transactions
    pub short_header_proofs: VecDeque<Vec<u8>>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    pub cache_prune_l2_heights: Vec<u64>,
    /// The witness needed to access the last L1 hash on the bitcoin light client contract
    pub last_l1_hash_witness: Witness,
}
