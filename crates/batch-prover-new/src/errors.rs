use std::fmt::Display;

pub enum L1ProcessingError {
    NoSeqCommitments {
        l1_height: u64,
    },
    DuplicateCommitments {
        l1_height: u64,
    },
    L2RangeMissing {
        start_block_number: u64,
        end_block_number: u64,
    },
    Other(String),
}

impl Display for L1ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L1ProcessingError::NoSeqCommitments { l1_height } => {
                write!(f, "No sequencer commitment found at height {}", l1_height)
            }
            L1ProcessingError::DuplicateCommitments { l1_height } => {
                write!(
                    f,
                    "All sequencer commitments are duplicates from a former DA block {}",
                    l1_height
                )
            }
            L1ProcessingError::L2RangeMissing {
                start_block_number,
                end_block_number,
            } => {
                write!(
                    f,
                    "L2 range of commitments is not synced yet {} - {}",
                    start_block_number, end_block_number
                )
            }
            L1ProcessingError::Other(e) => write!(f, "{}", e),
        }
    }
}
