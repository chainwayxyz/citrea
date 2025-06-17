//! This module provides functionality to partition sequencer commitments into groups based on various criteria.
//! It allows for efficient processing of commitments by creating partitions that can be handled independently.
//! The partitioning is based on several factors such as index gaps, spec changes, state diffs, and more.

use citrea_primitives::forks::get_tangerine_activation_height_non_zero;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::BatchProverLedgerOps;
use sov_rollup_interface::da::SequencerCommitment;
use tracing::info;

/// Enum to determine how to group commitments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionMode {
    /// Groups commitments with the default prover strategy
    Normal,
    /// Every commitment is a group on their own, generates a proof for every commitment
    OneByOne,
}

/// Reason why a new partition was created
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionReason {
    /// Partitions commitments one by one, each commitment is a separate partition
    /// This can be used when the partition mode is set to `OneByOne`
    /// e.g. [1], [2], [3] will create partitions for each commitment
    OneByOne,
    /// Partitions commitments by index gap, i.e. when there is a gap in the commitment indices
    /// e.g. [1, 2, 3, 5, 6] will create a partition for [1, 2, 3] and [6] because of the gap at index 4
    /// and the check from filtering commitments that do not have previous commitment
    IndexGap,
    /// Partitions commitments when a spec change is detected
    /// e.g. when the spec ID changes between two commitments
    /// [1, 2, 3] with spec ID 1 and [4] with spec ID 2 will create a partition for [1, 2, 3] and [4]
    SpecChange,
    /// Partitions commitments when the state diff exceeds a certain threshold
    /// If max state diff limit is surpassed
    /// eg [1, 2, 3] with state diff combined 350kb and [4] with state diff 100kb will exceed the 400kb limit
    /// and create a partition for [1, 2, 3] and [4]
    StateDiff,
    /// Partitions remaining commitments into one last partition if none of the above conditions are met
    Finish,
}

/// Helper struct to track the current state and ensure the integrity of the partition
pub struct PartitionState<'a, DB: BatchProverLedgerOps> {
    /// The sequencer commitments that are being partitioned
    commitments: &'a [SequencerCommitment],
    /// The partitions created so far
    partitions: Vec<Partition<'a>>,
    /// The start height of the next partition
    /// This is the L2 height of the first commitment in the next partition
    partition_start_height: u64,
    /// The index of the first commitment in the next partition
    /// This is the index in the commitments array, not the sequencer commitment index
    partition_start_idx: usize,
    /// The ledger database used to query previous commitments and their heights
    ledger_db: DB,
}

impl<'a, DB: BatchProverLedgerOps> PartitionState<'a, DB> {
    /// Creates a new `PartitionState` instance.
    ///
    /// # Arguments
    /// * `commitments` - A slice of sequencer commitments to be partitioned.
    /// * `ledger_db` - The database instance used to query previous commitments and their heights.
    ///
    /// # Returns
    /// A `PartitionState` instance initialized with the provided commitments and ledger database.
    pub fn new(commitments: &'a [SequencerCommitment], ledger_db: DB) -> anyhow::Result<Self> {
        let start_l2_height = if commitments[0].index == 1 {
            // If this is the first commitment ever, start from 1
            get_tangerine_activation_height_non_zero()
        } else {
            // If this is not the first commitment, start l2 height will be end block number + 1 of the previous commitment
            ledger_db
                .get_commitment_by_index(commitments[0].index - 1)?
                .expect("Previous commitment must exist")
                .l2_end_block_number
                + 1
        };

        Ok(Self {
            commitments,
            partitions: vec![],
            partition_start_height: start_l2_height,
            partition_start_idx: 0,
            ledger_db,
        })
    }

    /// Adds a new partition to the partition state.
    ///
    /// # Arguments
    /// * `end_idx` is the index to the commitments array, and it is inclusive.
    /// * `reason` is the reason for creating this partition, which can be used for logging or further processing.
    ///
    /// # Returns
    /// A result indicating success or failure. If successful, the partition is added to the state.
    pub fn add_partition(&mut self, end_idx: usize, reason: PartitionReason) -> anyhow::Result<()> {
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
            "Adding commitment partition: indices=[{},{}] blocks=[{},{}] reason={:?}",
            first_commitment.index,
            last_commitment.index,
            self.partition_start_height,
            last_commitment.l2_end_block_number,
            reason
        );

        // create a new partition
        let commitments = &self.commitments[self.partition_start_idx..=end_idx];
        self.partitions.push(Partition {
            commitments,
            start_height: self.partition_start_height,
            end_height: last_commitment.l2_end_block_number,
        });

        self.partition_start_idx = end_idx + 1;
        // if this was the last commitment, no need for further calculations
        if self.partition_start_idx == self.commitments.len() {
            return Ok(());
        }

        self.partition_start_height = match reason {
            PartitionReason::IndexGap => {
                // in case of index gap, we need to query the next partition's start height
                let first_commitment_of_next_partition =
                    &self.commitments[self.partition_start_idx];
                self.ledger_db
                    .get_commitment_by_index(first_commitment_of_next_partition.index - 1)?
                    .expect("Previous commitment must exist")
                    .l2_end_block_number
                    + 1
            }
            _ => last_commitment.l2_end_block_number + 1,
        };

        Ok(())
    }

    /// Returns the next partition start height, which is the L2 height of the first commitment in the next partition.
    pub fn next_partition_start_height(&self) -> u64 {
        self.partition_start_height
    }

    /// Returns the partition vector, which contains all the partitions created so far.
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
#[derive(Debug)]
pub struct Partition<'a> {
    /// The sequencer commitments that are part of this partition
    pub commitments: &'a [SequencerCommitment],
    /// The start height of the partition, which is the L2 height of the first commitment in this partition
    pub start_height: u64,
    /// The end height of the partition, which is the L2 height of the last commitment in this partition
    pub end_height: u64,
}
