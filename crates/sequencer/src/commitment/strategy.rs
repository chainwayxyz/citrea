use std::cmp;

use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::BatchNumber;
use tracing::debug;

use super::CommitmentInfo;

pub trait CommitmentStrategy {
    fn should_commit(&self) -> anyhow::Result<Option<CommitmentInfo>>;
}

pub(crate) struct MinSoftConfirmations<DB>
where
    DB: SequencerLedgerOps,
{
    pub(crate) ledger_db: DB,
    pub(crate) number: u64,
}

impl<DB: SequencerLedgerOps> CommitmentStrategy for MinSoftConfirmations<DB> {
    fn should_commit(&self) -> anyhow::Result<Option<CommitmentInfo>> {
        let Some((head_soft_confirmation_number, _)) =
            self.ledger_db.get_head_soft_confirmation()?
        else {
            // No soft confirmations have been created yet.
            return Ok(None);
        };
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
        if last_committed_l2_height >= head_soft_confirmation_number {
            // Already committed.
            return Ok(None);
        }

        let l2_start = last_committed_l2_height.0 + 1;
        let l2_end = head_soft_confirmation_number.0;

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

pub(crate) struct StateDiffThreshold {}

impl CommitmentStrategy for StateDiffThreshold {
    fn should_commit(&self) -> anyhow::Result<Option<CommitmentInfo>> {
        Ok(None)
    }
}

pub struct CommitmentController {
    strategies: Vec<Box<dyn CommitmentStrategy>>,
}

impl CommitmentController {
    pub fn new(strategies: Vec<Box<dyn CommitmentStrategy>>) -> Self {
        Self { strategies }
    }
}

impl CommitmentStrategy for CommitmentController {
    fn should_commit(&self) -> anyhow::Result<Option<CommitmentInfo>> {
        let mut commitment_infos: Vec<Option<CommitmentInfo>> = self
            .strategies
            .iter()
            .map(|strategy| strategy.should_commit())
            .flatten()
            .collect();
        commitment_infos.retain(|s| s.is_some());
        Ok(commitment_infos.first().cloned().flatten())
    }
}
