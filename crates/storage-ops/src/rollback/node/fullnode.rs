use std::sync::Arc;

use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByHash, L2BlockByNumber, L2RangeByL1Height, L2StatusHeights,
    ProverLastScannedSlot, SequencerCommitmentByIndex, ShortHeaderProofBySlotHash, SlotByHash,
    VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L2BlockNumber, L2HeightStatus, SlotNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct FullNodeLedgerRollback {
    ledger_db: Arc<DB>,
}

impl FullNodeLedgerRollback {
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
        }

        Ok(rollback_result)
    }

    fn rollback_slots_by_number(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut commitments_by_number = self.ledger_db.iter_with_direction::<CommitmentsByNumber>(
            Default::default(),
            ScanDirection::Backward,
        )?;
        commitments_by_number.seek_to_last();

        for record in commitments_by_number {
            let Ok(record) = record else {
                continue;
            };

            let slot_height = record.key;

            if slot_height <= SlotNumber(l1_target) {
                break;
            }

            self.ledger_db.delete::<L2RangeByL1Height>(&slot_height)?;
            increment_table_counter!("L2RangeByl1Height", rollback_result);

            self.ledger_db.delete::<CommitmentsByNumber>(&slot_height)?;
            increment_table_counter!("CommitmentsByNumber", rollback_result);

            self.ledger_db
                .delete::<VerifiedBatchProofsBySlotNumber>(&slot_height)?;
            increment_table_counter!("VerifiedBatchProofsBySlotNumber", rollback_result);
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

    fn rollback_l2_status_heights(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let last_scanned_l1_height = self.ledger_db.get::<ProverLastScannedSlot>(&())?;
        let last_scanned_l1_height = last_scanned_l1_height.unwrap_or_default();
        for l1_height in (l1_target..=last_scanned_l1_height.0).rev() {
            self.ledger_db
                .delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l1_height))?;
            increment_table_counter!("L2StatusHeights", rollback_result);

            self.ledger_db
                .delete::<L2StatusHeights>(&(L2HeightStatus::Proven, l1_height))?;
            increment_table_counter!("L2StatusHeights", rollback_result);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for FullNodeLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();
        rollback_result = self.rollback_l2(context.l2_target, rollback_result)?;
        rollback_result =
            self.rollback_commitments(context.last_sequencer_commitment_index, rollback_result)?;
        rollback_result = self.rollback_slots_by_number(context.l1_target, rollback_result)?;
        rollback_result = self.rollback_slots_by_hash(context.l1_target, rollback_result)?;
        rollback_result = self.rollback_l2_status_heights(context.l1_target, rollback_result)?;

        let _ = self
            .ledger_db
            .put::<ProverLastScannedSlot>(&(), &SlotNumber(context.l1_target));
        let _ = self.ledger_db.flush();
        Ok(rollback_result)
    }
}
