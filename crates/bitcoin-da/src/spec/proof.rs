//! Provides a proof for the inclusion of transactions in a block.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::spec::TransactionWrapper;

/// Set of proofs for inclusion of a transaction in a block
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct InclusionMultiProof {
    /// Witness transaction ids for the proof of inclusion in the block.
    pub wtxids: Vec<[u8; 32]>,
    /// The coinbase transaction that is used to prove the inclusion of the witness transactions.
    pub coinbase_tx: TransactionWrapper,
    /// Merkle proof for the coinbase transaction in the block.
    pub coinbase_merkle_proof: Vec<[u8; 32]>,
}

#[cfg(feature = "native")]
impl InclusionMultiProof {
    pub(crate) fn new(
        wtxids: Vec<[u8; 32]>,
        coinbase_tx: TransactionWrapper,
        coinbase_merkle_proof: Vec<[u8; 32]>,
    ) -> Self {
        InclusionMultiProof {
            wtxids,
            coinbase_tx,
            coinbase_merkle_proof,
        }
    }
}
