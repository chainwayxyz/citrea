use std::collections::HashMap;
use std::sync::Arc;

use sov_db::schema::tables::{
    CommitmentIndicesByJobId, CommitmentIndicesByL1, JobIdOfCommitment, L2BlockByHash,
    L2BlockByNumber, PendingL1SubmissionJobs, ProofByJobId, ProverLastScannedSlot,
    ProverPendingCommitments, ProverStateDiffs, SequencerCommitmentByIndex,
    ShortHeaderProofBySlotHash, SlotByHash,
};
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_schema_db::{ScanDirection, SchemaBatch, DB};

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct BatchProverLedgerRollback {
    ledger_db: Arc<DB>,
}

impl BatchProverLedgerRollback {
    pub fn new(ledger_db: Arc<DB>) -> Self {
        Self { ledger_db }
    }

    fn rollback_l2(&self, l2_target: u64, mut rollback_result: RollbackResult) -> Result {
        let mut batch = SchemaBatch::new();

        // Begin rollback for L2 tables
        let mut l2_blocks = self
            .ledger_db
            .iter_with_direction::<L2BlockByNumber>(Default::default(), ScanDirection::Backward)?;
        l2_blocks.seek_to_last();

        for record in l2_blocks {
            let record = record?;
            let l2_block_number = record.key;
            let l2_block_hash = record.value.hash;

            if l2_block_number <= L2BlockNumber(l2_target) {
                break;
            }

            batch.delete::<L2BlockByNumber>(&l2_block_number)?;
            increment_table_counter!("L2BlockByNumber", rollback_result);

            batch.delete::<ProverStateDiffs>(&l2_block_number)?;
            increment_table_counter!("ProverStateDiffs", rollback_result);

            batch.delete::<L2BlockByHash>(&l2_block_hash)?;
            increment_table_counter!("L2BlockByHash", rollback_result);
        }

        self.ledger_db.write_schemas(batch)?;

        Ok(rollback_result)
    }

    fn rollback_commitments(
        &self,
        last_sequencer_commitment_index: u32,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut batch = SchemaBatch::new();

        // First handle sequencer commitments
        let mut comm_iter = self
            .ledger_db
            .iter_with_direction::<SequencerCommitmentByIndex>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        comm_iter.seek_to_last();

        // Delete individual commitment entries
        for record in comm_iter {
            let comm_idx = record?.key;
            if comm_idx <= last_sequencer_commitment_index {
                break;
            }

            batch.delete::<SequencerCommitmentByIndex>(&comm_idx)?;
            increment_table_counter!("SequencerCommitmentByIndex", rollback_result);

            batch.delete::<JobIdOfCommitment>(&comm_idx)?;
            increment_table_counter!("JobIdOfCommitments", rollback_result);

            batch.delete::<ProverPendingCommitments>(&comm_idx)?;
            increment_table_counter!("ProverPendingCommitments", rollback_result);
        }

        // Now handle jobs that might contain commitments we're rolling back
        let mut jobs_iter = self
            .ledger_db
            .iter_with_direction::<CommitmentIndicesByJobId>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        jobs_iter.seek_to_last();

        // Collect jobs that have any indices above our rollback point
        for job_record in jobs_iter {
            let job_record = job_record?;
            let job_id = job_record.key;
            let commitment_indices = job_record.value;

            if !commitment_indices
                .iter()
                .all(|&idx| idx > last_sequencer_commitment_index)
            {
                tracing::warn!(
                    "Preserving job {}. Job indices: {:?}, rollback target: {}",
                    job_id,
                    commitment_indices,
                    last_sequencer_commitment_index
                );
                continue;
            }

            batch.delete::<CommitmentIndicesByJobId>(&job_id)?;
            increment_table_counter!("CommitmentIndicesByJobId", rollback_result);

            batch.delete::<PendingL1SubmissionJobs>(&job_id)?;
            increment_table_counter!("PendingL1SubmissionJobs", rollback_result);

            batch.delete::<ProofByJobId>(&job_id)?;
            increment_table_counter!("ProofByJobId", rollback_result);
        }

        self.ledger_db.write_schemas(batch)?;

        Ok(rollback_result)
    }

    fn rollback_slots(&self, l1_target: u64, mut rollback_result: RollbackResult) -> Result {
        let mut batch = SchemaBatch::new();

        let l1_cache = self.construct_l1_cache()?;

        let mut commitment_indices_by_l1 = self
            .ledger_db
            .iter_with_direction::<CommitmentIndicesByL1>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        commitment_indices_by_l1.seek_to_last();

        let mut last_deleted_slot = None;
        for record in commitment_indices_by_l1 {
            let l1_height = record?.key;

            if l1_height <= SlotNumber(l1_target) {
                break;
            }

            let iter_end = last_deleted_slot.unwrap_or(l1_height.0);
            for i in l1_height.0..=iter_end {
                batch.delete::<CommitmentIndicesByL1>(&SlotNumber(i))?;
                increment_table_counter!("CommitmentIndicesByl1", rollback_result);

                if let Some(slot_hash) = l1_cache.get(&i) {
                    batch.delete::<ShortHeaderProofBySlotHash>(slot_hash)?;
                    increment_table_counter!("ShortHeaderProofBySlotHash", rollback_result);
                    batch.delete::<SlotByHash>(slot_hash)?;
                    increment_table_counter!("SlotByHash", rollback_result);
                }
            }
            last_deleted_slot = Some(l1_height.0);
        }

        self.ledger_db.write_schemas(batch)?;

        Ok(rollback_result)
    }

    fn construct_l1_cache(&self) -> anyhow::Result<HashMap<u64, [u8; 32]>> {
        let mut cache = HashMap::new();
        let mut slots = self
            .ledger_db
            .iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Forward)?;
        slots.seek_to_first();

        // Cache L1 hash by L1 block number
        for record in slots {
            let Ok(record) = record else {
                continue;
            };

            cache.insert(record.value.0, record.key);
        }

        Ok(cache)
    }
}

impl LedgerNodeRollback for BatchProverLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();

        if let Some(l2_target) = context.l2_target {
            rollback_result = self.rollback_l2(l2_target, rollback_result)?;
        }

        if let Some(last_sequencer_commitment_index) = context.last_sequencer_commitment_index {
            rollback_result =
                self.rollback_commitments(last_sequencer_commitment_index, rollback_result)?;
        }

        if let Some(l1_target) = context.l1_target {
            rollback_result = self.rollback_slots(l1_target, rollback_result)?;

            let _ = self
                .ledger_db
                .put::<ProverLastScannedSlot>(&(), &SlotNumber(l1_target));
        }

        let _ = self.ledger_db.flush();
        Ok(rollback_result)
    }
}
