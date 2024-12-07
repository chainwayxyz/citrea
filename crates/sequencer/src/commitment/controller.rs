use std::cmp;

use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TXBODY_SIZE;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::StateDiff;
use tracing::{debug, warn};

use super::CommitmentInfo;

// Based on the test runs, brotli is able to compress the state diff 58% to 70%,
// with an average of 66% for both empty and full blocks. This is a super safe
// estimation of 33% compression.
const SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE: usize = MAX_TXBODY_SIZE * 3 / 2;

pub struct CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    min_soft_confirmations: u64,
    last_state_diff: StateDiff,
}

impl<Db> CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    pub fn new(ledger_db: Db, min_soft_confirmations: u64) -> Self {
        let last_state_diff = ledger_db.get_state_diff().unwrap_or_default();
        Self {
            ledger_db,
            min_soft_confirmations,
            last_state_diff,
        }
    }

    pub fn should_commit(
        &mut self,
        l2_height: u64,
        l2_state_diff: StateDiff,
    ) -> anyhow::Result<Option<CommitmentInfo>> {
        // Get latest finalized and pending commitments and find the max height
        let last_finalized_l2_height = self
            .ledger_db
            .get_last_commitment_l2_height()?
            .unwrap_or(BatchNumber(0));
        let last_pending_l2_height = self
            .ledger_db
            .get_pending_commitments_l2_range()?
            .iter()
            .map(|(_, end)| *end)
            .max()
            .unwrap_or(BatchNumber(0));
        let last_committed_l2_height = cmp::max(last_finalized_l2_height, last_pending_l2_height);

        // If block state diff is empty, it is certain that state diff threshold won't be exceeded.
        let updated_state_diff = if !l2_state_diff.is_empty() {
            // It is OK to take value of last_state_diff here to avoid cloning the value.
            // It is not used anywhere except this point, and it will certainly be set to a new value.
            let last_state_diff = std::mem::take(&mut self.last_state_diff);
            let merged_state_diff = merge_state_diffs(last_state_diff, l2_state_diff.clone());

            // Check if state diff threshold is reached
            if let Some(info) = self.check_state_diff_threshold(
                last_committed_l2_height,
                l2_height,
                &merged_state_diff,
            ) {
                // New state diff is current L2 block's state diff, because the current block is not
                // included in the commitment if threshold is exceeded.
                self.set_state_diff(l2_state_diff)?;
                return Ok(Some(info));
            }

            Some(merged_state_diff)
        } else {
            None
        };

        // Check if soft confirmation threshold is reached
        if let Some(info) = self.check_min_soft_confirmations(last_committed_l2_height, l2_height) {
            // Clear state diff
            self.set_state_diff(vec![])?;
            return Ok(Some(info));
        }

        if let Some(updated_state_diff) = updated_state_diff {
            // If no threshold is met, update the state diff to merged state diff
            self.set_state_diff(updated_state_diff)?;
        }

        Ok(None)
    }

    fn check_min_soft_confirmations(
        &self,
        last_committed_l2_height: BatchNumber,
        current_l2_height: u64,
    ) -> Option<CommitmentInfo> {
        // If the last commitment made is on par with the head
        // soft confirmation, we have already committed the latest block.
        if last_committed_l2_height.0 >= current_l2_height {
            warn!(
                last_committed = last_committed_l2_height.0,
                current = current_l2_height,
                "Got L2 height lower than the last committed L2 height."
            );
            return None;
        }

        let l2_start = last_committed_l2_height.0 + 1;
        let l2_end = current_l2_height;

        let l2_range_length = 1 + l2_end - l2_start;
        if l2_range_length < self.min_soft_confirmations {
            return None;
        }

        debug!("Enough soft confirmations to submit commitment");
        Some(CommitmentInfo {
            l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
        })
    }

    fn check_state_diff_threshold(
        &self,
        last_committed_l2_height: BatchNumber,
        current_l2_height: u64,
        state_diff: &StateDiff,
    ) -> Option<CommitmentInfo> {
        if state_diff.is_empty() {
            return None;
        }

        let uncompressed_state_diff =
            borsh::to_vec(state_diff).expect("State diff serialization can not fail");
        // Early return if uncompressed state diff doesn't exceed limit
        if uncompressed_state_diff.len() <= SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE {
            return None;
        }

        let compressed_state_diff = compress_blob(&uncompressed_state_diff);
        if compressed_state_diff.len() <= MAX_TXBODY_SIZE {
            return None;
        }

        let l2_start = last_committed_l2_height.0 + 1;
        // We don't include the current l2 block, or else tx body is going to be greater than limit
        let l2_end = current_l2_height - 1;
        assert!(
            l2_end >= l2_start,
            "Have a sequencer commitment with single L2 block which won't fit into a DA tx"
        );

        debug!("Enough state diff size to submit commitment");
        Some(CommitmentInfo {
            l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
        })
    }

    fn set_state_diff(&mut self, state_diff: StateDiff) -> anyhow::Result<()> {
        self.ledger_db.set_state_diff(&state_diff)?;
        self.last_state_diff = state_diff;
        Ok(())
    }
}
