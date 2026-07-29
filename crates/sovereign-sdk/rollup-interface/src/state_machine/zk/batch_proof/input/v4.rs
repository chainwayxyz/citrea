use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::block::{L2Block, L2Header};
use crate::da::SequencerCommitment;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the v4 elf input
pub struct BatchProofCircuitInputV4Part1 {
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

/// Pre-computed ecrecover pubkey witnesses.
///
/// Holds the uncompressed 65-byte pubkeys recovered from the signatures
/// of the L2 blocks in that commitment, in circuit consumption order.
pub type EcrecoverPubkeyWitnesses = Vec<[u8; 65]>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the v4 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV4Part2(pub EcrecoverPubkeyWitnesses);

type InputV4Part3<Witness> = VecDeque<Vec<(u64, L2Block, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Third part of the v4 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV4Part3(pub InputV4Part3<Witness>);

/// Legacy batch-proof input layout.
pub type LegacyBatchProofInput = (BatchProofCircuitInputV4Part1, BatchProofCircuitInputV4Part3);

/// Batch-proof input V4 layout.
pub type BatchProofCircuitInputV4Parts = (
    BatchProofCircuitInputV4Part1,
    BatchProofCircuitInputV4Part2,
    BatchProofCircuitInputV4Part3,
);

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// Data required to verify a state transition.
/// This is more like a glue type to create V1/V2/V3 batch proof circuit inputs later in the program
pub struct BatchProofCircuitInputV4 {
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
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    pub cache_prune_l2_heights: Vec<u64>,
    /// Witness needed to get the last Bitcoin hash on Bitcoin Light Client contract
    pub last_l1_hash_witness: Witness,
    /// The sequencer commitment immediately before the first commitment being proven.
    /// `None` means this is the first batch proof. Otherwise the index must be
    /// `sequencer_commitments[0].index - 1`.
    pub previous_sequencer_commitment: Option<SequencerCommitment>,
    /// To verify the first `prev_hash`, we need a merkle proof for the last header in the previous
    /// sequencer commitment.
    pub prev_hash_proof: Option<PrevHashProof>,
    /// Pre-computed ecrecover pubkey witnesses.
    pub ecrecover_pubkey_witnesses: EcrecoverPubkeyWitnesses,
}

impl BatchProofCircuitInputV4 {
    fn into_shared_parts(self) -> BatchProofCircuitInputV4Parts {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut part3 = VecDeque::with_capacity(self.l2_blocks.len());

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

            part3.push_back(v);
        }

        let part1 = BatchProofCircuitInputV4Part1 {
            initial_state_root: self.initial_state_root,
            previous_sequencer_commitment: self.previous_sequencer_commitment,
            prev_hash_proof: self.prev_hash_proof,
            sequencer_commitments: self.sequencer_commitments,
            short_header_proofs: self.short_header_proofs,
            cache_prune_l2_heights: self.cache_prune_l2_heights,
            last_l1_hash_witness: self.last_l1_hash_witness,
        };

        (
            part1,
            BatchProofCircuitInputV4Part2(self.ecrecover_pubkey_witnesses),
            BatchProofCircuitInputV4Part3(part3),
        )
    }

    /// Build the legacy input layout. Pubkey witnesses are intentionally
    /// dropped because older circuits recover pubkeys in-VM.
    pub fn into_legacy_parts(self) -> LegacyBatchProofInput {
        let (part1, _part2, part3) = self.into_shared_parts();
        (part1, part3)
    }

    /// Build the V4 input layout.
    pub fn into_v4_parts(self) -> BatchProofCircuitInputV4Parts {
        self.into_shared_parts()
    }
}
