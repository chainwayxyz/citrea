use std::collections::VecDeque;

use super::v3::{BatchProofCircuitInputV3Part1, BatchProofCircuitInputV3Part2, PrevHashProof};
use crate::block::L2Block;
use crate::da::SequencerCommitment;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

/// Pre-computed ecrecover pubkey witnesses, grouped by sequencer commitment.
///
/// Each inner `Vec` holds the uncompressed 65-byte pubkeys recovered from the
/// signatures of the L2 blocks in that commitment, in circuit consumption order.
pub type EcrecoverPubkeyWitnesses = VecDeque<Vec<[u8; 65]>>;

/// Legacy batch-proof input layout.
pub type LegacyBatchProofInput = (BatchProofCircuitInputV3Part1, BatchProofCircuitInputV3Part2);

/// Batch-proof input V4 layout.
pub type BatchProofCircuitInputV4Parts = (
    BatchProofCircuitInputV3Part1,
    EcrecoverPubkeyWitnesses,
    BatchProofCircuitInputV3Part2,
);

/// Host-side batch-proof input data for the V4 layout.
///
/// Reuses the V3 `Part1`/`Part2` parts on the wire and adds, for forks that
/// activate it, one pre-computed ecrecover pubkey-witness stream item between
/// them. The host serializes this either as the legacy V3 input or as the
/// pubkey-witness input, depending on the active fork.
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
    fn into_shared_parts(
        self,
    ) -> (
        BatchProofCircuitInputV3Part1,
        EcrecoverPubkeyWitnesses,
        BatchProofCircuitInputV3Part2,
    ) {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut part2 = VecDeque::with_capacity(self.l2_blocks.len());

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

            part2.push_back(v);
        }

        let part1 = BatchProofCircuitInputV3Part1 {
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
            self.ecrecover_pubkey_witnesses,
            BatchProofCircuitInputV3Part2(part2),
        )
    }

    /// Build the legacy input layout. Pubkey witnesses are intentionally
    /// dropped because older circuits recover pubkeys in-VM.
    pub fn into_legacy_parts(self) -> LegacyBatchProofInput {
        let (part1, _ecrecover_pubkey_witnesses, part2) = self.into_shared_parts();
        (part1, part2)
    }

    /// Build the V4 input layout.
    pub fn into_v4_parts(self) -> BatchProofCircuitInputV4Parts {
        self.into_shared_parts()
    }
}
