use std::collections::VecDeque;

use borsh::BorshSerialize;

use crate::da::DaSpec;
use crate::soft_confirmation::L2Block;
use crate::witness::PreFork2Witness;
use crate::zk::StorageRootHash;

/// Second part of the Kumquat elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV2Part2<'txs, Tx: Clone + BorshSerialize>(
    pub VecDeque<Vec<(L2Block<'txs, Tx>, PreFork2Witness, PreFork2Witness)>>,
);

impl<'txs, Tx: Clone + BorshSerialize> BorshSerialize for BatchProofCircuitInputV2Part2<'txs, Tx> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&(self.0.len() as u32), writer)?;
        for blocks in &self.0 {
            BorshSerialize::serialize(&(blocks.len() as u32), writer)?;
            for (block, w1, w2) in blocks {
                block.serialize_v2(writer)?;
                w1.serialize(writer)?;
                w2.serialize(writer)?;
            }
        }
        Ok(())
    }
}

#[derive(BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the Kumquat elf input
pub struct BatchProofCircuitInputV2Part1<Da: DaSpec> {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The state root after the state transition
    pub final_state_root: StorageRootHash,
    /// The hash before the state transition
    pub prev_soft_confirmation_hash: [u8; 32],
    /// DA block header that the sequencer commitments were found in.
    pub da_block_header_of_commitments: Da::BlockHeader,
    /// The inclusion proof for all DA data.
    pub inclusion_proof: Da::InclusionMultiProof,
    /// The completeness proof for all DA data.
    pub completeness_proof: Da::CompletenessProof,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
    /// DA block headers the L2 blocks were constructed on.
    pub da_block_headers_of_l2_blocks: VecDeque<Vec<Da::BlockHeader>>,
    /// The range of sequencer commitments that are being processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
}
