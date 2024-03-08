use bitcoin::absolute::{Height, LockTime};
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

// Set of proofs for inclusion of a transaction in a block
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InclusionMultiProof {
    pub txs: Vec<[u8; 32]>,
    pub wtxids: Vec<[u8; 32]>,
    pub coinbase_tx: Transaction,
}

impl Default for InclusionMultiProof {
    fn default() -> Self {
        InclusionMultiProof {
            txs: vec![],
            wtxids: vec![],
            coinbase_tx: Transaction {
                version: 0,
                lock_time: LockTime::Blocks(Height::min_value()),
                input: vec![],
                output: vec![],
            },
        }
    }
}
