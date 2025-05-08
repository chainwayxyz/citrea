use std::sync::Arc;

use sov_db::schema::tables::{
    CommitmentIndicesByL1, JobIdOfCommitment, L2BlockByHash, L2BlockByNumber, L2StatusHeights,
    ProofsBySlotNumber, ProofsBySlotNumberV2, ProverLastScannedSlot, ProverPendingCommitments,
    ProverStateDiffs, SequencerCommitmentByIndex, ShortHeaderProofBySlotHash, SlotByHash,
};
use sov_db::schema::types::{L2BlockNumber, L2HeightStatus, SlotNumber};
use sov_schema_db::{ScanDirection, DB};

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

            self.ledger_db.delete::<L2BlockByNumber>(&l2_block_number)?;
            increment_table_counter!("L2BlockByNumber", rollback_result);

            self.ledger_db
                .delete::<ProverStateDiffs>(&l2_block_number)?;
            increment_table_counter!("ProverStateDiffs", rollback_result);

            self.ledger_db.delete::<L2BlockByHash>(&l2_block_hash)?;
            increment_table_counter!("L2BlockByHash", rollback_result);

            self.ledger_db
                .delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l2_block_number.0))?;
            increment_table_counter!("L2StatusHeights", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_commitments(
        &self,
        last_sequencer_commitment_index: u32,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut comm_iter = self
            .ledger_db
            .iter_with_direction::<SequencerCommitmentByIndex>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        comm_iter.seek_to_last();

        for record in comm_iter {
            let comm_idx = record?.key;
            if comm_idx <= last_sequencer_commitment_index {
                break;
            }

            self.ledger_db
                .delete::<SequencerCommitmentByIndex>(&comm_idx)?;
            increment_table_counter!("SequencerCommitmentByIndex", rollback_result);

            self.ledger_db.delete::<JobIdOfCommitment>(&comm_idx)?;
            increment_table_counter!("JobIdOfCommitments", rollback_result);

            self.ledger_db
                .delete::<ProverPendingCommitments>(&comm_idx)?;
            increment_table_counter!("ProverPendingCommitments", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_slots_by_number(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut commitment_indices_by_l1 = self
            .ledger_db
            .iter_with_direction::<CommitmentIndicesByL1>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        commitment_indices_by_l1.seek_to_last();

        for record in commitment_indices_by_l1 {
            let l1_height = record?.key;

            if l1_height <= SlotNumber(l1_target) {
                break;
            }

            self.ledger_db.delete::<CommitmentIndicesByL1>(&l1_height)?;
            increment_table_counter!("CommitmentIndicesByl1", rollback_result);
            self.ledger_db.delete::<ProofsBySlotNumber>(&l1_height)?;
            increment_table_counter!("ProofsBySlotNumber", rollback_result);
            self.ledger_db.delete::<ProofsBySlotNumberV2>(&l1_height)?;
            increment_table_counter!("ProofsBySlotNumberV2", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_slots_by_hash(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut slots = self
            .ledger_db
            .iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Backward)?;
        slots.seek_to_last();

        for record in slots {
            let Ok(record) = record else {
                continue;
            };

            if record.value <= SlotNumber(l1_target) {
                break;
            }

            self.ledger_db
                .delete::<ShortHeaderProofBySlotHash>(&record.key)?;
            increment_table_counter!("ShortHeaderProofBySlotHash", rollback_result);
            self.ledger_db.delete::<SlotByHash>(&record.key)?;
            increment_table_counter!("SlotByHash", rollback_result);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for BatchProverLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();
        rollback_result = self.rollback_l2(context.l2_target, rollback_result)?;
        rollback_result =
            self.rollback_commitments(context.last_sequencer_commitment_index, rollback_result)?;
        rollback_result = self.rollback_slots_by_hash(context.l1_target, rollback_result)?;
        rollback_result = self.rollback_slots_by_number(context.l1_target, rollback_result)?;

        let _ = self
            .ledger_db
            .put::<ProverLastScannedSlot>(&(), &SlotNumber(context.l1_target));
        let _ = self.ledger_db.flush();
        Ok(rollback_result)
    }
}
