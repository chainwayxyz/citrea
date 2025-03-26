use anyhow::ensure;
use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TXBODY_SIZE;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use tracing::debug;

use super::service::CommitmentRange;

// Based on the test runs, brotli is able to compress the state diff 58% to 70%,
// with an average of 66% for both empty and full blocks. This is a super safe
// estimation of 50% compression.
const SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE: usize = MAX_TXBODY_SIZE * 2;

pub struct CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    min_l2_blocks: u64,
}

impl<Db> CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    pub fn new(ledger_db: Db, min_l2_blocks: u64) -> Self {
        Self {
            ledger_db,
            min_l2_blocks,
        }
    }

    pub fn should_commit(
        &mut self,
        from_l2_height: L2BlockNumber,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        // Check if state diff threshold is reached
        if let Some(info) = self.check_state_diff_threshold(from_l2_height, to_l2_height)? {
            // New state diff is current L2 block's state diff, because the current block is not
            // included in the commitment if threshold is exceeded.
            return Ok(Some(info));
        }

        // Check if l2 block threshold is reached
        if let Some(info) = self.check_min_l2_blocks(from_l2_height, to_l2_height)? {
            // Clear state diff
            return Ok(Some(info));
        }

        Ok(None)
    }

    fn check_min_l2_blocks(
        &self,
        from_l2_height: L2BlockNumber,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        let l2_start = from_l2_height.0 + 1;
        let l2_end = to_l2_height.0;
        // If the last commitment made is on par with the head
        // l2 block, we have already committed the latest block.
        ensure!(
            l2_end >= l2_start,
            "Got L2 height lower than the last committed L2 height."
        );

        let l2_range_length = 1 + l2_end - l2_start;
        if l2_range_length < self.min_l2_blocks {
            return Ok(None);
        }

        debug!("Enough l2 blocks to submit commitment");

        Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_end)))
    }

    fn check_state_diff_threshold(
        &self,
        from_l2_height: L2BlockNumber,
        to_l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        let l2_start = from_l2_height.0 + 1;
        // We don't include the current l2 block, or else tx body is going to be greater than limit
        let l2_end = to_l2_height.0 - 1;
        ensure!(
            l2_end >= l2_start,
            "Have a sequencer commitment with single L2 block which won't fit into a DA tx"
        );

        let mut merged_state_diff = vec![];
        for l2_height in l2_start..=l2_end {
            let state_diff = self.ledger_db.get_state_diff(L2BlockNumber(l2_height))?;
            merged_state_diff = merge_state_diffs(merged_state_diff, state_diff);
        }

        let uncompressed_state_diff =
            borsh::to_vec(&merged_state_diff).expect("State diff serialization can not fail");
        // Early return if uncompressed state diff doesn't exceed limit
        if uncompressed_state_diff.len() <= SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE {
            return Ok(None);
        }

        let compressed_state_diff = compress_blob(&uncompressed_state_diff).unwrap();
        if compressed_state_diff.len() <= MAX_TXBODY_SIZE {
            return Ok(None);
        }

        debug!("Enough state diff size to submit commitment");
        Ok(Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_end)))
    }
}
