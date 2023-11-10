use serde::{Deserialize, Serialize};

// Set of proofs for inclusion of a transaction in a block
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InclusionMultiProof {
    pub txs: Vec<[u8; 32]>,
}
