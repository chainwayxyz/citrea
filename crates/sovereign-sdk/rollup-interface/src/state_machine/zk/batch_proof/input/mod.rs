use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use v2::{BatchProofCircuitInputV2Part1, BatchProofCircuitInputV2Part2};
use v3::{BatchProofCircuitInputV3Part1, BatchProofCircuitInputV3Part2};

use crate::da::{DaSpec, SequencerCommitment};
use crate::soft_confirmation::SignedSoftConfirmation;
use crate::zk::StorageRootHash;

/// Genesis input module
pub mod v1;
/// Kumquat input module
pub mod v2;
/// Fork2 input module
/// Removes dependency on da_data so we input less data to the circuit
pub mod v3;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// Data required to verify a state transition.
/// This is more like a glue type to create V1/V2 batch proof circuit inputs later in the program
pub struct BatchProofCircuitInput<'txs, Witness, Da: DaSpec, Tx: Clone> {
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
    /// The soft confirmations that are inside the sequencer commitments.
    pub soft_confirmations: VecDeque<Vec<SignedSoftConfirmation<'txs, Tx>>>,
    /// Corresponding witness for the soft confirmations.
    pub state_transition_witnesses: VecDeque<Vec<(Witness, Witness)>>,
    /// DA block headers the soft confirmations was constructed on.
    pub da_block_headers_of_soft_confirmations: VecDeque<Vec<Da::BlockHeader>>,
    /// Sequencer soft confirmation public key.
    /// **DO NOT USE THIS FIELD IN POST FORK1 GUEST**
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public_key: Vec<u8>,
    /// **DO NOT USE THIS FIELD IN POST FORK1 GUEST**
    pub sequencer_da_public_key: Vec<u8>,
    /// The range of sequencer commitments that are being processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer commitments that will be proven.
    /// Only applies to V3
    pub sequencer_commitments: Vec<SequencerCommitment>,
}

impl<'txs, Witness, Da, Tx> BatchProofCircuitInput<'txs, Witness, Da, Tx>
where
    Da: DaSpec,
    Tx: Clone,
    Witness: Serialize + DeserializeOwned,
{
    /// Into Kumquat expected inputs
    pub fn into_v2_parts(
        self,
    ) -> (
        BatchProofCircuitInputV2Part1<Da>,
        BatchProofCircuitInputV2Part2<'txs, Witness, Tx>,
    ) {
        assert_eq!(
            self.soft_confirmations.len(),
            self.state_transition_witnesses.len()
        );
        let mut x = VecDeque::with_capacity(self.soft_confirmations.len());

        let v2_confirmations = self
            .soft_confirmations
            .into_iter()
            .map(|confirmations| {
                confirmations
                    .into_iter()
                    .map(SignedSoftConfirmation::from)
                    .collect::<Vec<_>>()
            })
            .collect::<VecDeque<_>>();

        for (confirmations, witnesses) in v2_confirmations
            .into_iter()
            .zip(self.state_transition_witnesses)
        {
            assert_eq!(confirmations.len(), witnesses.len());

            let v: Vec<_> = confirmations
                .into_iter()
                .zip(witnesses)
                .map(|(confirmation, (state_witness, offchain_witness))| {
                    (confirmation, state_witness, offchain_witness)
                })
                .collect();

            x.push_back(v);
        }

        (
            BatchProofCircuitInputV2Part1 {
                initial_state_root: self.initial_state_root,
                final_state_root: self.final_state_root,
                prev_soft_confirmation_hash: self.prev_soft_confirmation_hash,
                da_data: self.da_data,
                da_block_header_of_commitments: self.da_block_header_of_commitments,
                inclusion_proof: self.inclusion_proof,
                completeness_proof: self.completeness_proof,
                preproven_commitments: self.preproven_commitments,
                da_block_headers_of_soft_confirmations: self.da_block_headers_of_soft_confirmations,
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
        BatchProofCircuitInputV3Part2<'txs, Witness, Tx>,
    ) {
        assert_eq!(
            self.soft_confirmations.len(),
            self.state_transition_witnesses.len()
        );
        let mut x = VecDeque::with_capacity(self.soft_confirmations.len());

        for (confirmations, witnesses) in self
            .soft_confirmations
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
                da_block_headers_of_soft_confirmations: self.da_block_headers_of_soft_confirmations,
                sequencer_commitments: self.sequencer_commitments,
            },
            BatchProofCircuitInputV3Part2(x),
        )
    }
}
