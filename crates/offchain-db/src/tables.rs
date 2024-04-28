use std::fmt;

pub enum Tables {
    /// string version is sequencer_commitment
    SequencerCommitment,
}

// impl to_string for tables
impl fmt::Display for Tables {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Tables::SequencerCommitment => write!(f, "sequencer_commitment"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DbSequencerCommitment {
    /// Hex encoded L1 transaction ID
    pub l1_tx_id: String,
    pub l1_start_heiht: u32,
    pub l1_end_height: u32,
    /// Hex encoded L1 start hash
    pub l1_start_hash: String,
    /// Hex encoded L1 end hash
    pub l1_end_hash: String,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    /// Hex encoded merkle root of soft confirmation hashes
    pub merkle_root: String,
    pub status: String,
}

///// Merkle root of soft confirmation hashes
///pub merkle_root: [u8; 32],

pub(crate) const SEQUENCER_COMMITMENT_TABLE: &str = "
CREATE TABLE IF NOT EXISTS sequencer_commitment (
    id                  SERIAL PRIMARY KEY,
    l1_start_height     OID NOT NULL,
    l1_end_height       OID NOT NULL,
    l1_tx_id            VARCHAR(66) NOT NULL,
    l1_start_hash       VARCHAR(66) NOT NULL,
    l1_end_hash         VARCHAR(66) NOT NULL,
    l2_start_height     OID NOT NULL,
    l2_end_height       OID NOT NULL,
    merkle_root         VARCHAR(66) NOT NULL,
    status              VARCHAR(15) NOT NULL              
    );
";
