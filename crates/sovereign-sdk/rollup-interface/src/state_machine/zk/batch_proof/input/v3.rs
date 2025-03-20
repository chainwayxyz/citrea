use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::block::L2Block;
use crate::da::SequencerCommitment;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

type InputV3Part2<Witness> = VecDeque<Vec<(u64, L2Block, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Fork2 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2(pub InputV3Part2<Witness>);

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the Kumquat elf input
pub struct BatchProofCircuitInputV3Part1 {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The sequencer commitment before the first sequencer commitment in the sequencer_commitments vector
    /// If it is none than this is the first batch proof
    /// Else the index of the sequencer commitment should be `sequencer_commitments[0].index - 1``
    pub previous_sequencer_commitment: Option<SequencerCommitment>,
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
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// Data required to verify a state transition.
/// This is more like a glue type to create V1/V2 batch proof circuit inputs later in the program
pub struct BatchProofCircuitInputV3 {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The state root after the state transition
    pub final_state_root: StorageRootHash,
    /// The L2 blocks that are inside the sequencer commitments.
    pub l2_blocks: VecDeque<Vec<L2Block>>,
    /// Corresponding witness for the l2 blocks.
    pub state_transition_witnesses: VecDeque<Vec<(Witness, Witness)>>,
    /// Short header proofs for verifying system transactions
    pub short_header_proofs: VecDeque<Vec<u8>>,
    /// Sequencer commitments that will be proven.
    /// Only applies to V3
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    /// Only applies to V3
    pub cache_prune_l2_heights: Vec<u64>,
    /// Witness needed to get the last Bitcoin hash on Bitcoin Light Client contract
    pub last_l1_hash_witness: Witness,
    /// The sequencer commitment before the first sequencer commitment in the sequencer_commitments vector
    /// If it is none than this is the first batch proof
    /// Else the index of the sequencer commitment should be `sequencer_commitments[0].index - 1``
    pub previous_sequencer_commitment: Option<SequencerCommitment>,
}

impl BatchProofCircuitInputV3 {
    /// Into Fork2 expected inputs
    pub fn into_v3_parts(self) -> (BatchProofCircuitInputV3Part1, BatchProofCircuitInputV3Part2) {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut x = VecDeque::with_capacity(self.l2_blocks.len());

        for (l2_blocks, witnesses) in self
            .l2_blocks
            .into_iter()
            .zip(self.state_transition_witnesses)
        {
            assert_eq!(l2_blocks.len(), witnesses.len());

            let v: Vec<_> = l2_blocks
                .into_iter()
                .zip(witnesses)
                .map(|(l2_block, (state_witness, offchain_witness))| {
                    (l2_block.height(), l2_block, state_witness, offchain_witness)
                })
                .collect();

            x.push_back(v);
        }

        (
            BatchProofCircuitInputV3Part1 {
                initial_state_root: self.initial_state_root,
                short_header_proofs: self.short_header_proofs,
                sequencer_commitments: self.sequencer_commitments,
                cache_prune_l2_heights: self.cache_prune_l2_heights,
                last_l1_hash_witness: self.last_l1_hash_witness,
                previous_sequencer_commitment: self.previous_sequencer_commitment,
            },
            BatchProofCircuitInputV3Part2(x),
        )
    }
}
