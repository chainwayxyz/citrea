use sov_db::ledger_db::{LedgerDBTransaction, TransactionLedgerDB};
use sov_db::schema::tables::{LightClientProofBySlotNumber, ProverLastScannedSlot};
use sov_db::schema::types::SlotNumber;
use sov_schema_db::ScanDirection;

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct LightClientLedgerRollback {
    ledger_db: TransactionLedgerDB,
}

impl LightClientLedgerRollback {
    pub fn new(ledger_db: TransactionLedgerDB) -> Self {
        Self { ledger_db }
    }

    fn rollback_slots_by_number(
        tx: &LedgerDBTransaction,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut proof_by_slot_number = tx.iter_with_direction::<LightClientProofBySlotNumber>(
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

            tx.delete::<LightClientProofBySlotNumber>(&slot_height)?;
            increment_table_counter!("LightClientProofBySlotNumber", rollback_result);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for LightClientLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();

        // Begin rollback for each component
        let tx = self.ledger_db.transaction();

        if let Some(l1_target) = context.l1_target {
            rollback_result = Self::rollback_slots_by_number(&tx, l1_target, rollback_result)?;

            tx.put::<ProverLastScannedSlot>(&(), &SlotNumber(l1_target))?;
        }

        tx.commit()?;
        Ok(rollback_result)
    }
}
