use sov_db::ledger_db::{LedgerDBTransaction, TransactionLedgerDB};
use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByHash, L2BlockByNumber, L2RangeByL1Height,
    SequencerCommitmentByIndex, StateDiffByBlockNumber,
};
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_schema_db::ScanDirection;

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct SequencerLedgerRollback {
    ledger_db: TransactionLedgerDB,
}

impl SequencerLedgerRollback {
    pub fn new(ledger_db: TransactionLedgerDB) -> Self {
        Self { ledger_db }
    }

    fn rollback_l2(
        tx: &LedgerDBTransaction,
        l2_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut l2_blocks =
            tx.iter_with_direction::<L2BlockByNumber>(Default::default(), ScanDirection::Backward)?;
        l2_blocks.seek_to_last();

        for record in l2_blocks {
            let record = record?;
            let l2_block_number = record.key;
            let l2_block_hash = record.value.hash;

            if l2_block_number <= L2BlockNumber(l2_target) {
                break;
            }

            tx.delete::<L2BlockByNumber>(&l2_block_number)?;
            increment_table_counter!("L2BlockByNumber", rollback_result);

            tx.delete::<L2BlockByHash>(&l2_block_hash)?;
            increment_table_counter!("L2BlockByHash", rollback_result);

            tx.delete::<StateDiffByBlockNumber>(&l2_block_number)?;
            increment_table_counter!("StateDiffByBlockNumber", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_commitments(
        tx: &LedgerDBTransaction,
        last_sequencer_commitment_index: u32,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut comm_iter = tx.iter_with_direction::<SequencerCommitmentByIndex>(
            Default::default(),
            ScanDirection::Backward,
        )?;
        comm_iter.seek_to_last();

        for record in comm_iter {
            let comm_idx = record?.key;
            if comm_idx <= last_sequencer_commitment_index {
                break;
            }

            tx.delete::<SequencerCommitmentByIndex>(&comm_idx)?;
            increment_table_counter!("SequencerCommitmentByIndex", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_slots(
        tx: &LedgerDBTransaction,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut commitments_by_number = tx.iter_with_direction::<CommitmentsByNumber>(
            Default::default(),
            ScanDirection::Backward,
        )?;
        commitments_by_number.seek_to_last();

        let mut last_deleted_slot = None;
        for record in commitments_by_number {
            let Ok(record) = record else {
                continue;
            };

            let slot_height = record.key;

            if slot_height <= SlotNumber(l1_target) {
                break;
            }

            let iter_end = last_deleted_slot.unwrap_or(slot_height.0);
            for i in slot_height.0..=iter_end {
                tx.delete::<L2RangeByL1Height>(&SlotNumber(i))?;
                increment_table_counter!("L2RangeByL1Height", rollback_result);

                tx.delete::<CommitmentsByNumber>(&SlotNumber(i))?;
                increment_table_counter!("CommitmentsByNumber", rollback_result);
            }
            last_deleted_slot = Some(slot_height.0);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for SequencerLedgerRollback {
    fn execute(&self, context: RollbackContext) -> Result {
        let mut rollback_result = RollbackResult::default();

        // Begin rollback for each component
        let tx = self.ledger_db.transaction();

        if let Some(l2_target) = context.l2_target {
            rollback_result = Self::rollback_l2(&tx, l2_target, rollback_result)?;
        }

        if let Some(last_sequencer_commitment_index) = context.last_sequencer_commitment_index {
            rollback_result =
                Self::rollback_commitments(&tx, last_sequencer_commitment_index, rollback_result)?;
        }

        if let Some(l1_target) = context.l1_target {
            rollback_result = Self::rollback_slots(&tx, l1_target, rollback_result)?;
        }

        tx.commit()?;

        Ok(rollback_result)
    }
}
