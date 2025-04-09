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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionReason {
    OneByOne,
    IndexGap,
    SpecChange,
    StateDiff,
    Finish,
}

/// Helper struct to track the current state and ensure the integrity of the partition
pub struct PartitionState<'a, DB: BatchProverLedgerOps> {
    commitments: &'a [SequencerCommitment],
    partitions: Vec<Partition<'a>>,
    partition_start_height: u64,
    partition_start_idx: usize,
    ledger_db: DB,
}

impl<'a, DB: BatchProverLedgerOps> PartitionState<'a, DB> {
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

    /// Adds a new partition. end_idx is the index to the commitments array, and it is inclusive.
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
                // in case of index gap, we need to query the next partition start height
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

    pub fn next_partition_start_height(&self) -> u64 {
        self.partition_start_height
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
