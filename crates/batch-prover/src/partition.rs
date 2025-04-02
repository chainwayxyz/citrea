use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::SequencerCommitment;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Enum to determine how to group commitments
pub enum PartitionMode {
    /// Groups commitments the normal way
    /// Generates proof(s) given l1 height using the same strategy of batch prover
    Normal,
    /// Every commitment is a group on their own
    /// Generates a proof for every commitment
    OneByOne,
}

pub struct PartitionState<'a> {
    commitments: &'a [SequencerCommitment],
    partitions: Vec<Partition<'a>>,
    pub partition_start_height: u64,
    pub partition_start_idx: usize,
}

impl<'a> PartitionState<'a> {
    pub fn new(commitments: &'a [SequencerCommitment], start_l2_height: u64) -> Self {
        Self {
            commitments,
            partitions: vec![],
            partition_start_height: start_l2_height,
            partition_start_idx: 0,
        }
    }

    /// Adds a new partition. end_idx is the index to the commitments array, and it is inclusive.
    pub fn add_partition(&mut self, end_idx: usize, reason: &str) {
        assert!(
            end_idx >= self.partition_start_idx,
            "incorrectly ordered end partition index"
        );
        assert!(
            end_idx < self.commitments.len(),
            "end index higher than commitment count"
        );

        let first_commitment = &self.commitments[self.partition_start_idx];
        let last_commitment = &self.commitments[end_idx];

        info!(
            "Adding commitment partition: indices=[{},{}] blocks=[{},{}] reason={}",
            first_commitment.index,
            last_commitment.index,
            self.partition_start_height,
            last_commitment.l2_end_block_number,
            reason
        );

        let commitments = &self.commitments[self.partition_start_idx..=end_idx];
        self.partitions.push(Partition {
            commitments,
            start_height: self.partition_start_height,
            end_height: last_commitment.l2_end_block_number,
        });

        self.partition_start_idx = end_idx + 1;
        self.partition_start_height = last_commitment.l2_end_block_number + 1;
    }

    pub fn into_inner(self) -> Vec<Partition<'a>> {
        assert_eq!(
            self.partition_start_idx,
            self.commitments.len(),
            "trying to finalize partition without adding all commitments"
        );
        self.partitions
    }
}

/// Helper wrapper struct to hold start and end heights with the commitment partition
pub struct Partition<'a> {
    pub commitments: &'a [SequencerCommitment],
    pub start_height: u64,
    pub end_height: u64,
}
