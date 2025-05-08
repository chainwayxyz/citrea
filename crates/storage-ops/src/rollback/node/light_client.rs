use std::sync::Arc;

use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByNumber, L2RangeByL1Height, LightClientProofBySlotNumber,
    ProverLastScannedSlot,
};
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct LightClientLedgerRollback {
    ledger_db: Arc<DB>,
}

impl LightClientLedgerRollback {
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

            if l2_block_number <= L2BlockNumber(l2_target) {
                break;
            }

            self.ledger_db.delete::<L2BlockByNumber>(&l2_block_number)?;
            increment_table_counter!("L2BlockByNumber", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_slots_by_number(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut proof_by_slot_number = self
            .ledger_db
            .iter_with_direction::<LightClientProofBySlotNumber>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        proof_by_slot_number.seek_to_last();

        for record in proof_by_slot_number {
            let Ok(record) = record else {
                continue;
            };

            let slot_height = record.key;

            if slot_height <= SlotNumber(l1_target) {
                break;
            }

            self.ledger_db
                .delete::<LightClientProofBySlotNumber>(&slot_height)?;
            increment_table_counter!("LightClientProofBySlotNumber", rollback_result);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for LightClientLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();
        rollback_result = self.rollback_l2(context.l2_target, rollback_result)?;
        rollback_result = self.rollback_slots_by_number(context.l1_target, rollback_result)?;

        let _ = self
            .ledger_db
            .put::<ProverLastScannedSlot>(&(), &SlotNumber(context.l1_target));
        let _ = self.ledger_db.flush();
        Ok(rollback_result)
    }
}
