use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::spec::TransactionWrapper;

// Set of proofs for inclusion of a transaction in a block
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct InclusionMultiProof {
    pub wtxids: Vec<[u8; 32]>,
    pub coinbase_tx: TransactionWrapper,
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

impl Default for InclusionMultiProof {
    fn default() -> Self {
        InclusionMultiProof {
            wtxids: vec![],
            coinbase_tx: TransactionWrapper::empty(),
            coinbase_merkle_proof: Vec::new(),
        }
    }
}
