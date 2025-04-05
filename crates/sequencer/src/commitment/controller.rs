use std::ops::RangeInclusive;

use anyhow::ensure;
use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TXBODY_SIZE;
use parking_lot::Mutex;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_modules_api::StateDiff;
use tracing::debug;

use super::service::CommitmentRange;

// Based on the test runs, brotli is able to compress the state diff 58% to 70%,
// with an average of 66% for both empty and full blocks. This is a super safe
// estimation of 50% compression.
const SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE: usize = MAX_TXBODY_SIZE * 2;

/// Keeps track of the accumulated state diff ever since the last committed L2 block.
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
    state_diff: Mutex<AccumulatedStateDiff>,
}

impl<Db> CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    pub fn new(ledger_db: Db, max_l2_blocks: u64) -> Self {
        let state_diff = Mutex::new(
            Self::construct_merged_state_diff(&ledger_db)
                .expect("Should be able to construct existing state diff"),
        );
        Self {
            ledger_db,
            max_l2_blocks,
            state_diff,
        }
    }

    pub fn should_commit(
        &self,
        from_l2_height: L2BlockNumber,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        // Check if state diff threshold is reached
        if let Some(info) = self.check_state_diff_threshold(to_l2_height)? {
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

    fn construct_merged_state_diff(ledger_db: &Db) -> anyhow::Result<AccumulatedStateDiff> {
        let start_l2_height = ledger_db
            .get_last_commitment()?
            .map(|c| c.l2_end_block_number)
            .unwrap_or(1)
            + 1; // Start should be last committed height + 1
        let end_l2_height = ledger_db
            .get_head_l2_block()?
            .map(|(height, _)| height)
            .unwrap_or(L2BlockNumber(1))
            .0;

        let mut merged_state_diff = vec![];
        for l2_height in start_l2_height..=end_l2_height {
            let state_diff = ledger_db.get_state_diff(L2BlockNumber(l2_height))?;
            merged_state_diff = merge_state_diffs(merged_state_diff, state_diff);
        }

        Ok(AccumulatedStateDiff {
            height: end_l2_height,
            diff: merged_state_diff,
        })
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
            if compressed_state_diff.len() > MAX_TXBODY_SIZE {
                debug!("Enough state diff size to submit commitment");
                return Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_height)));
            }
        }

        Ok(None)
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
