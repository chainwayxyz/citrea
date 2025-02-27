use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
use v2::{BatchProofCircuitInputV2Part1, BatchProofCircuitInputV2Part2};
use v3::{BatchProofCircuitInputV3Part1, BatchProofCircuitInputV3Part2};

use crate::da::{DaSpec, SequencerCommitment};
use crate::soft_confirmation::L2Block;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

/// Genesis input module
pub mod v1;
/// Kumquat input module
pub mod v2;
/// Fork2 input module
/// Removes dependency on da_data so we input less data to the circuit
pub mod v3;

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// Data required to verify a state transition.
/// This is more like a glue type to create V1/V2 batch proof circuit inputs later in the program
pub struct BatchProofCircuitInput<'txs, Da: DaSpec, Tx: Clone + BorshSerialize> {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The state root after the state transition
    pub final_state_root: StorageRootHash,
    /// The hash before the state transition
    pub prev_soft_confirmation_hash: [u8; 32],
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
    /// The L2 blocks that are inside the sequencer commitments.
    pub l2_blocks: VecDeque<Vec<L2Block<'txs, Tx>>>,
    /// Corresponding witness for the soft confirmations.
    pub state_transition_witnesses: VecDeque<Vec<(Witness, Witness)>>,
    /// DA block headers the L2 block was constructed on.
    pub da_block_headers_of_l2_blocks: VecDeque<Vec<Da::BlockHeader>>,
    /// Sequencer soft confirmation public key.
    /// **DO NOT USE THIS FIELD IN POST FORK1 GUEST**
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public_key: Vec<u8>,
    /// **DO NOT USE THIS FIELD IN POST FORK1 GUEST**
    pub sequencer_da_public_key: Vec<u8>,
    /// The range of sequencer commitments that are being processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
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
}

impl<'txs, Da, Tx> BatchProofCircuitInput<'txs, Da, Tx>
where
    Da: DaSpec,
    Tx: Clone + BorshSerialize,
{
    /// Into Kumquat expected inputs
    pub fn into_v2_parts(
        self,
    ) -> (
        BatchProofCircuitInputV2Part1<Da>,
        BatchProofCircuitInputV2Part2<'txs, Tx>,
    ) {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut x = VecDeque::with_capacity(self.l2_blocks.len());

        for (confirmations, witnesses) in self
            .l2_blocks
            .into_iter()
            .zip(self.state_transition_witnesses)
        {
            assert_eq!(confirmations.len(), witnesses.len());

            let v: Vec<_> = confirmations
                .into_iter()
                .zip(witnesses)
                .map(|(confirmation, (state_witness, offchain_witness))| {
                    (confirmation, state_witness.into(), offchain_witness.into())
                })
                .collect();

            x.push_back(v);
        }

        (
            BatchProofCircuitInputV2Part1 {
                initial_state_root: self.initial_state_root,
                final_state_root: self.final_state_root,
                prev_soft_confirmation_hash: self.prev_soft_confirmation_hash,
                da_block_header_of_commitments: self.da_block_header_of_commitments,
                inclusion_proof: self.inclusion_proof,
                completeness_proof: self.completeness_proof,
                preproven_commitments: self.preproven_commitments,
                da_block_headers_of_l2_blocks: self.da_block_headers_of_l2_blocks,
                sequencer_commitments_range: self.sequencer_commitments_range,
            },
            BatchProofCircuitInputV2Part2(x),
        )
    }

    /// Into Kumquat expected inputs
    pub fn into_v3_parts(
        self,
    ) -> (
        BatchProofCircuitInputV3Part1<Da>,
        BatchProofCircuitInputV3Part2<'txs, Tx>,
    ) {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut x = VecDeque::with_capacity(self.l2_blocks.len());

        for (confirmations, witnesses) in self
            .l2_blocks
            .into_iter()
            .zip(self.state_transition_witnesses)
        {
            assert_eq!(confirmations.len(), witnesses.len());

            let v: Vec<_> = confirmations
                .into_iter()
                .zip(witnesses)
                .map(|(confirmation, (state_witness, offchain_witness))| {
                    (
                        confirmation.l2_height(),
                        confirmation,
                        state_witness,
                        offchain_witness,
                    )
                })
                .collect();

            x.push_back(v);
        }

        (
            BatchProofCircuitInputV3Part1 {
                initial_state_root: self.initial_state_root,
                short_header_proofs: self.short_header_proofs,
                da_block_headers_of_soft_confirmations: self.da_block_headers_of_l2_blocks,
                sequencer_commitments: self.sequencer_commitments,
                cache_prune_l2_heights: self.cache_prune_l2_heights,
                last_l1_hash_witness: self.last_l1_hash_witness,
            },
            BatchProofCircuitInputV3Part2(x),
        )
    }
}
