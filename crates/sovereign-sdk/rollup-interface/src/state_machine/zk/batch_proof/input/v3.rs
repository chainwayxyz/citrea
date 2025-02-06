use alloc::collections::VecDeque;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::da::{DaSpec, SequencerCommitment};
use crate::soft_confirmation::SignedSoftConfirmation;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Kumquat elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2<'txs, Witness, Tx: Clone>(
    pub VecDeque<Vec<(SignedSoftConfirmation<'txs, Tx>, Witness, Witness)>>,
);

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
#[serde(bound = "StateRoot: Serialize + DeserializeOwned")]
/// First part of the Kumquat elf input
pub struct BatchProofCircuitInputV3Part1<StateRoot, Da: DaSpec> {
    /// The state root before the state transition
    pub initial_state_root: StateRoot,
    /// The state root after the state transition
    pub final_state_root: StateRoot,
    /// The hash before the state transition
    pub prev_soft_confirmation_hash: [u8; 32],
    /// Sequencer commitments being proven
    /// Since `SequencerCommitment` does not have the sequencer's signature,
    /// the light client prover will be doing the signature verification
    /// when it is extracting the commitments from L1
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// DA block headers the soft confirmations was constructed on.
    pub da_block_headers_of_soft_confirmations: VecDeque<Vec<Da::BlockHeader>>,
}
