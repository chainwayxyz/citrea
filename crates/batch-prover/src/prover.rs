use sov_db::ledger_db::BatchProverLedgerOps;
use sov_db::schema::types::UnprovenCommitmentStatus;
use sov_rollup_interface::da::SequencerCommitment;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct Prover<DB>
where
    DB: BatchProverLedgerOps,
{
    ledger_db: DB,
    l1_signal_rx: mpsc::Receiver<()>,
    l2_block_rx: broadcast::Receiver<u64>,
    sync_target_l2_height: Option<u64>,
}

impl<DB> Prover<DB>
where
    DB: BatchProverLedgerOps,
{
    pub fn new(
        ledger_db: DB,
        l1_signal_rx: mpsc::Receiver<()>,
        l2_block_rx: broadcast::Receiver<u64>,
    ) -> Self {
        Self {
            ledger_db,
            l1_signal_rx,
            l2_block_rx,
            sync_target_l2_height: None,
        }
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    return;
                }
                l1_signal = self.l1_signal_rx.recv() => {
                    l1_signal.expect("L1 signal sender channel closed abruptly");

                    if let Err(e) = self.try_proving().await {
                        error!("Failed to start proving: {:?}", e);
                    }
                },
                l2_signal = self.l2_block_rx.recv() => {
                    let l2_height = l2_signal.expect("L2 signal sender channel closed abruptly");
                    let Some(sync_target_l2_height) = self.sync_target_l2_height else {
                        // we are already fully synced or no commitments are waiting for l2 blocks, ignore
                        continue;
                    };

                    if l2_height < sync_target_l2_height {
                        // new l2 height has not yet reached the next sync target, ignore
                        continue;
                    }
                }
            }
        }
    }

    async fn try_proving(&mut self) -> anyhow::Result<()> {
        let commitments = self.get_unproven_commitments(Some(UnprovenCommitmentStatus::Pending))?;
        if commitments.is_empty() {
            return Ok(());
        }

        let commitments = self.filter_unsynced_commitments(commitments)?;
        info!("Have {} provable commitment(s)", commitments.len());
        if commitments.is_empty() {
            return Ok(());
        }

        let start_block_number = if commitments[0].index == 0 {
            // If this is the first commitment ever, start from 1
            1
        } else {
            let previous_commitment_index = commitments[0].index - 1;
            // If this is not the first commitment in fork2, the start l2 height will be the end block number of the previous commitment
            self.ledger_db
                .get_commitment_by_index(previous_commitment_index)?
                .expect("Previous commitment must exist")
                .l2_end_block_number
                + 1
        };

        Ok(())
    }

    fn get_unproven_commitments(
        &self,
        filter_status: Option<UnprovenCommitmentStatus>,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let unproven_commitment_indices = self.ledger_db.get_unproven_commitments(filter_status)?;

        let mut commitments = Vec::with_capacity(unproven_commitment_indices.len());
        for index in unproven_commitment_indices {
            let commitment = self
                .ledger_db
                .get_commitment_by_index(index)?
                .expect("Unproven commitment must exist by index");
            commitments.push(commitment);
        }

        Ok(commitments)
    }

    /// Filters out the commitments that prover l2 blocks not synced to yet
    fn filter_unsynced_commitments(
        &mut self,
        mut commitments: Vec<SequencerCommitment>,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let head_l2_height = self
            .ledger_db
            .get_head_l2_block_height()?
            .expect("Head l2 block height must exist in db");
        let l2_end_block_number = commitments
            .last()
            .expect("Commitments must not be empty")
            .l2_end_block_number;

        if l2_end_block_number <= head_l2_height {
            // short circuit for fully synced case
            self.sync_target_l2_height = None;
            return Ok(commitments);
        }

        // find first commitment position that is not synced
        let unsynced_pos = commitments
            .iter()
            .position(|comm| comm.l2_end_block_number > head_l2_height)
            .expect("Just ensured that at least one commitment is not synced");

        let sync_target_l2_height = commitments[unsynced_pos].l2_end_block_number;
        self.sync_target_l2_height = Some(sync_target_l2_height);

        let unsynced_count = commitments.drain(unsynced_pos..).count();

        warn!(
            "Only synced up to height {}, ignoring {} commitments, next sync target height is {}",
            head_l2_height, unsynced_count, sync_target_l2_height
        );

        Ok(commitments)
    }
}
