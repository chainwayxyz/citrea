use alloc::collections::VecDeque;
use alloc::vec::Vec;

use borsh::BorshSerialize;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::BatchProofCircuitInput;
use crate::da::{BlobReaderTrait, DaSpec};
use crate::soft_confirmation::SignedSoftConfirmationV1;

#[derive(Serialize, Deserialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
#[serde(bound = "StateRoot: Serialize + DeserializeOwned, Witness: Serialize + DeserializeOwned")]
/// Data required to verify a state transition.
pub struct BatchProofCircuitInputV1<StateRoot, Witness, Da: DaSpec> {
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
    pub soft_confirmations: VecDeque<Vec<SignedSoftConfirmationV1>>,
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
impl<StateRoot: borsh::BorshSerialize, Witness: borsh::BorshSerialize, Da: DaSpec> BorshSerialize
    for BatchProofCircuitInputV1<StateRoot, Witness, Da>
{
    /// Pre fork 1 serialization
    /// An additional [u8; 32] is added to the end of the bitcoin da header
    /// So the genesis fork guest fails to deserialize the header
    /// So we remove the last 32 bytes of the header while serializing
    /// This means Genesis 1 seraialization is not compatible with Mock DA
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.initial_state_root, writer)?;
        BorshSerialize::serialize(&self.final_state_root, writer)?;
        BorshSerialize::serialize(&self.initial_batch_hash, writer)?;

        // We write each blob tx as serialized into v1
        BorshSerialize::serialize(&(self.da_data.len() as u32), writer)?;
        for blob in &self.da_data {
            let bytes = blob.serialize_v1()?;
            writer.write_all(&bytes)?;
        }

        // remove last 32 bytes
        let original = borsh::to_vec(&self.da_block_header_of_commitments)?;
        writer.write_all(&original[..original.len() - 32])?;
        BorshSerialize::serialize(&self.inclusion_proof, writer)?;
        BorshSerialize::serialize(&self.completeness_proof, writer)?;
        BorshSerialize::serialize(&self.preproven_commitments, writer)?;
        BorshSerialize::serialize(&self.soft_confirmations, writer)?;
        BorshSerialize::serialize(&self.state_transition_witnesses, writer)?;

        // for every Da::BlockHeader we serialize it and remove last 32 bytes
        writer
            .write_all(&(self.da_block_headers_of_soft_confirmations.len() as u32).to_le_bytes())?;
        for header_vec in &self.da_block_headers_of_soft_confirmations {
            writer.write_all(&(header_vec.len() as u32).to_le_bytes())?;
            for header in header_vec {
                let original = borsh::to_vec(header)?;
                writer.write_all(&original[..original.len() - 32])?;
            }
        }

        BorshSerialize::serialize(&self.sequencer_public_key, writer)?;
        BorshSerialize::serialize(&self.sequencer_da_public_key, writer)?;
        BorshSerialize::serialize(&self.sequencer_commitments_range, writer)?;

        Ok(())
    }
}

impl<'txs, StateRoot, Witness, Da, Tx>
    From<BatchProofCircuitInput<'txs, StateRoot, Witness, Da, Tx>>
    for BatchProofCircuitInputV1<StateRoot, Witness, Da>
where
    Da: DaSpec,
    Tx: Clone,
    StateRoot: Serialize + DeserializeOwned,
    Witness: Serialize + DeserializeOwned,
{
    fn from(input: BatchProofCircuitInput<'txs, StateRoot, Witness, Da, Tx>) -> Self {
        BatchProofCircuitInputV1 {
            initial_state_root: input.initial_state_root,
            final_state_root: input.final_state_root,
            initial_batch_hash: input.prev_soft_confirmation_hash,
            da_data: input.da_data,
            da_block_header_of_commitments: input.da_block_header_of_commitments,
            inclusion_proof: input.inclusion_proof,
            completeness_proof: input.completeness_proof,
            preproven_commitments: input.preproven_commitments,
            soft_confirmations: input
                .soft_confirmations
                .into_iter()
                .map(|confirmations| {
                    confirmations
                        .into_iter()
                        .map(SignedSoftConfirmationV1::from)
                        .collect()
                })
                .collect(),
            state_transition_witnesses: input
                .state_transition_witnesses
                .into_iter()
                .map(|witnesses| witnesses.into_iter().map(|(witness, _)| witness).collect())
                .collect(),
            da_block_headers_of_soft_confirmations: input.da_block_headers_of_soft_confirmations,
            sequencer_public_key: input.sequencer_public_key,
            sequencer_da_public_key: input.sequencer_da_public_key,
            sequencer_commitments_range: input.sequencer_commitments_range,
        }
    }
}
