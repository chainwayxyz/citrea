use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::da::{DaSpec, SequencerCommitment};
use crate::soft_confirmation::L2Block;
use crate::zk::StorageRootHash;

type InputV3Part2<'txs, Tx, Witness> = VecDeque<Vec<(u64, L2Block<'txs, Tx>, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Fork2 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2<'txs, Witness, Tx: Clone + BorshSerialize>(
    pub InputV3Part2<'txs, Tx, Witness>,
);

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
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
    pub short_header_proofs: VecDeque<([u8; 32], Vec<u8>)>,
}
