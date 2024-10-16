use std::cmp;
use std::sync::Arc;

use citrea_common::compression::compress_blob;
use citrea_common::utils::merge_state_diffs;
use citrea_primitives::MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::StateDiff;
use tracing::debug;

use super::CommitmentInfo;

pub trait CommitmentStrategy {
    fn should_commit(
        &mut self,
        l2_height: u64,
        l2_state_diff: StateDiff,
    ) -> anyhow::Result<Option<CommitmentInfo>>;
}

pub(crate) struct MinSoftConfirmations<Db>
where
    Db: SequencerLedgerOps,
{
    ledger_db: Arc<Db>,
    number: u64,
}

impl<Db: SequencerLedgerOps> MinSoftConfirmations<Db> {
    pub fn new(ledger_db: Arc<Db>, number: u64) -> Self {
        Self { ledger_db, number }
    }
}

impl<Db: SequencerLedgerOps> CommitmentStrategy for MinSoftConfirmations<Db> {
    fn should_commit(
        &mut self,
        l2_height: u64,
        _l2_state_diff: StateDiff,
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

        // If the last commitment made is on par with the head
        // soft confirmation, we have already committed the latest block.
        if last_committed_l2_height.0 >= l2_height {
            // Already committed.
            return Ok(None);
        }

        let l2_start = last_committed_l2_height.0 + 1;
        let l2_end = l2_height;

        let l2_range_length = 1 + l2_end - l2_start;
        if l2_range_length < self.number {
            return Ok(None);
        }

        debug!("Enough soft confirmations to submit commitment");
        Ok(Some(CommitmentInfo {
            l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
        }))
    }
}

pub(crate) struct StateDiffThreshold<Db>
where
    Db: SequencerLedgerOps,
{
    ledger_db: Arc<Db>,
    last_state_diff: StateDiff,
}

impl<Db: SequencerLedgerOps> StateDiffThreshold<Db> {
    pub fn new(ledger_db: Arc<Db>) -> Self {
        let last_state_diff = ledger_db.get_state_diff().unwrap_or_default();
        Self {
            ledger_db,
            last_state_diff,
        }
    }
}

impl<Db> CommitmentStrategy for StateDiffThreshold<Db>
where
    Db: SequencerLedgerOps,
{
    fn should_commit(
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

        let merged_state_diff =
            merge_state_diffs(self.last_state_diff.clone(), l2_state_diff.clone());
        let compressed_state_diff = compress_blob(&borsh::to_vec(&merged_state_diff)?);

        // Threshold is checked by comparing compressed state diff size as the data will be compressed before it is written on DA
        let state_diff_threshold_reached =
            compressed_state_diff.len() as u64 > MAX_STATEDIFF_SIZE_COMMITMENT_THRESHOLD;

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
        let l2_end = l2_height;

        debug!("State diff threshold reached. Committing...");
        Ok(Some(CommitmentInfo {
            l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
        }))
    }
}

pub struct CommitmentController {
    strategies: Vec<Box<dyn CommitmentStrategy + Send + Sync + 'static>>,
}

impl CommitmentController {
    pub fn new(strategies: Vec<Box<dyn CommitmentStrategy + Send + Sync + 'static>>) -> Self {
        Self { strategies }
    }
}

impl CommitmentStrategy for CommitmentController {
    fn should_commit(
        &mut self,
        l2_height: u64,
        l2_state_diff: StateDiff,
    ) -> anyhow::Result<Option<CommitmentInfo>> {
        let mut commitment_infos: Vec<Option<CommitmentInfo>> = self
            .strategies
            .iter_mut()
            .flat_map(|strategy| strategy.should_commit(l2_height, l2_state_diff.clone()))
            .collect();
        commitment_infos.retain(|s| s.is_some());
        Ok(commitment_infos.first().cloned().flatten())
    }
}
