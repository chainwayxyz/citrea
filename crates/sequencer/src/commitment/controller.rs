use std::cmp;

use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TXBODY_SIZE;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::StateDiff;
use tracing::{debug, warn};

use super::CommitmentInfo;

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

        match self.check_min_soft_confirmations(last_committed_l2_height, l2_height) {
            Some(commitment_info) => Ok(Some(commitment_info)),
            None => Ok(self.check_state_diff_threshold(
                last_committed_l2_height,
                l2_height,
                l2_state_diff,
            )?),
        }
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
            // Already committed.
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
        &mut self,
        last_committed_l2_height: BatchNumber,
        current_l2_height: u64,
        l2_state_diff: StateDiff,
    ) -> anyhow::Result<Option<CommitmentInfo>> {
        let merged_state_diff =
            merge_state_diffs(self.last_state_diff.clone(), l2_state_diff.clone());
        let compressed_state_diff = compress_blob(&borsh::to_vec(&merged_state_diff)?);

        // Threshold is checked by comparing compressed state diff size as the data will be compressed before it is written on DA
        let state_diff_threshold_reached = compressed_state_diff.len() > MAX_TXBODY_SIZE;

        if state_diff_threshold_reached {
            self.last_state_diff.clone_from(&l2_state_diff);
            self.ledger_db
                .set_state_diff(self.last_state_diff.clone())?;
        } else {
            // Store state diff.
            self.last_state_diff = merged_state_diff;
            self.ledger_db
                .set_state_diff(self.last_state_diff.clone())?;
        }

        if !state_diff_threshold_reached {
            return Ok(None);
        }

        let l2_start = last_committed_l2_height.0 + 1;
        let l2_end = current_l2_height;

        debug!("State diff threshold reached. Committing...");
        Ok(Some(CommitmentInfo {
            l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
        }))
    }
}
