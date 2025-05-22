use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use anyhow::ensure;
use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TX_BODY_SIZE;
use parking_lot::Mutex;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_modules_api::StateDiff;
use tracing::debug;

use super::helpers::load_next_commitment_index_and_start_height;
use super::service::CommitmentRange;

// Based on the test runs, brotli is able to compress the state diff 58% to 70%,
// with an average of 66% for both empty and full blocks. This is a super safe
// estimation of 50% compression.
const SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE: usize = MAX_TX_BODY_SIZE * 2;

/// Keeps track of the accumulated state diff ever since the last committed L2 block.
#[derive(Default)]
struct AccumulatedStateDiff {
    height: u64,
    diff: StateDiff,
}

pub struct CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    max_l2_blocks: u64,
    next_commitment_index: AtomicU32,
    next_commitment_start_height: AtomicU64,
    state_diff: Mutex<AccumulatedStateDiff>,
}

impl<Db> CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    /// Initializes the `CommitmentController` and returns the commitment ranges if commitments
    /// can be constructed due to either state diff or max l2 blocks constraints.
    pub fn init(ledger_db: Db, max_l2_blocks: u64) -> (Self, Vec<CommitmentRange>) {
        let (next_index, next_start_height) =
            load_next_commitment_index_and_start_height(&ledger_db);
        // initialize the state diff just after the last commitment
        let state_diff = AccumulatedStateDiff {
            height: next_start_height - 1,
            diff: StateDiff::new(),
        };

        let controller = Self {
            ledger_db,
            max_l2_blocks,
            next_commitment_index: AtomicU32::new(next_index),
            next_commitment_start_height: AtomicU64::new(next_start_height),
            state_diff: Mutex::new(state_diff),
        };

        let head_l2_height = controller
            .ledger_db
            .get_head_l2_block_height()
            .expect("Failed to get head l2 block");
        let commitment_ranges = match head_l2_height {
            Some(head_l2_height) => {
                controller
                    .update_head_l2_height(L2BlockNumber(head_l2_height))
                    .expect("Should be able to construct existing state diff")
            }
            None => {
                // chain is just initialized, do some sanity checks
                assert_eq!(next_index, 1);
                assert_eq!(next_start_height, 1);
                vec![]
            }
        };

        (controller, commitment_ranges)
    }

    pub fn update_head_l2_height(
        &self,
        l2_height: L2BlockNumber,
    ) -> anyhow::Result<Vec<CommitmentRange>> {
        assert!(
            to_l2_height.0 >= self.next_commitment_start_height(),
            "should_commit called with l2 height lower than commitment start height"
        );

        // Check if state diff threshold is reached
        if let Some(info) = self.check_state_diff_threshold(to_l2_height)? {
            tracing::warn!("Checked state diff threshold: {:?}", info);
            // New state diff is current L2 block's state diff, because the current block is not
            // included in the commitment if threshold is exceeded.
            return Ok(Some(info));
        }

        // Check if l2 block threshold is reached
        if let Some(info) = self.check_max_l2_blocks(from_l2_height, to_l2_height)? {
            // Clear state diff
            return Ok(Some(info));
        }

        Ok(None)
    }

    fn check_max_l2_blocks(
        &self,
        from_l2_height: L2BlockNumber,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        let l2_start = from_l2_height.0;
        let l2_end = to_l2_height.0;
        // If the last commitment made is on par with the head
        // l2 block, we have already committed the latest block.
        ensure!(
            l2_end >= l2_start,
            "Got L2 height lower than the last committed L2 height."
        );

        let l2_range_length = 1 + l2_end - l2_start;
        if l2_range_length < self.max_l2_blocks {
            return Ok(None);
        }

        debug!("Enough l2 blocks to submit commitment");

        Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_end)))
    }

    fn check_state_diff_threshold(
        &self,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        let mut merged_state_diff = self.state_diff.lock();

        let l2_start = merged_state_diff.height + 1;
        // We don't include the current l2 block, or else tx body is going to be greater than limit
        let l2_end = to_l2_height.0 - 1;
        tracing::warn!("l2start: {}", l2_start);
        tracing::warn!("l2end: {}", l2_end);

        if l2_end < l2_start {
            return Ok(None);
        }

        for l2_height in l2_start..=l2_end {
            let state_diff = self.ledger_db.get_state_diff(L2BlockNumber(l2_height))?;
            merged_state_diff.diff = merge_state_diffs(merged_state_diff.diff.clone(), state_diff);
            merged_state_diff.height = l2_height;

            let uncompressed_state_diff = borsh::to_vec(&merged_state_diff.diff)
                .expect("State diff serialization can not fail");
            // Early return if uncompressed state diff doesn't exceed limit
            if uncompressed_state_diff.len() > SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE {
                debug!("Enough state diff size to submit commitment");
                return Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_height)));
            }

            let compressed_state_diff = compress_blob(&uncompressed_state_diff).unwrap();
            if compressed_state_diff.len() > MAX_TX_BODY_SIZE {
                debug!("Enough state diff size to submit commitment");
                return Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_height)));
            }
        }

        Ok(None)
    }

    fn next_commitment_start_height(&self) -> u64 {
        self.next_commitment_start_height.load(Ordering::SeqCst)
    }

    pub(crate) fn reset(&self) {
        let mut merged_state_diff = self.state_diff.lock();
        merged_state_diff.diff = vec![];
    }

    pub(crate) fn clear_commitment_state_diffs(
        &self,
        range: RangeInclusive<u64>,
    ) -> anyhow::Result<()> {
        for i in range {
            self.ledger_db.delete_state_diff(L2BlockNumber(i))?;
        }

        Ok(())
    }
}
