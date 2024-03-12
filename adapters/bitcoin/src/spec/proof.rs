use bitcoin::absolute::{LockTime, Time};
use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

// Set of proofs for inclusion of a transaction in a block
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InclusionMultiProof {
    pub txids: Vec<[u8; 32]>,
    pub wtxids: Vec<[u8; 32]>,
    pub coinbase_tx: Transaction,
}

impl InclusionMultiProof {
    pub(crate) fn new(
        txids: Vec<[u8; 32]>,
        wtxids: Vec<[u8; 32]>,
        coinbase_tx: Transaction,
    ) -> Self {
        InclusionMultiProof {
            txids,
            wtxids,
            coinbase_tx,
        }
    }
}

impl Default for InclusionMultiProof {
    fn default() -> Self {
        InclusionMultiProof {
            txids: vec![],
            wtxids: vec![],
            coinbase_tx: Transaction {
                version: 0,
                lock_time: LockTime::Seconds(Time::MIN),
                input: vec![],
                output: vec![],
            },
        }
    }
}
