use std::collections::HashMap;
use std::sync::Arc;

use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByHash, L2BlockByNumber, L2RangeByL1Height, L2StatusHeights,
    PendingProofs, PendingSequencerCommitments, ProverLastScannedSlot, SequencerCommitmentByIndex,
    ShortHeaderProofBySlotHash, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L2BlockNumber, L2HeightStatus, SlotNumber};
use sov_schema_db::{ScanDirection, SchemaBatch, DB};

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

            batch.delete::<SequencerCommitmentByIndex>(&comm_idx)?;
            increment_table_counter!("SequencerCommitmentByIndex", rollback_result);

            batch.delete::<PendingSequencerCommitments>(&comm_idx)?;
            increment_table_counter!("PendingSequencerCommitments", rollback_result);
        }

        self.ledger_db.write_schemas(batch)?;
        Ok(rollback_result)
    }

    fn rollback_slots(&self, l1_target: u64, mut rollback_result: RollbackResult) -> Result {
        let mut batch = SchemaBatch::new();
        let l1_cache = self.construct_l1_cache()?;
        let mut commitments_by_number = self.ledger_db.iter_with_direction::<CommitmentsByNumber>(
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
                batch.delete::<L2RangeByL1Height>(&SlotNumber(i))?;
                increment_table_counter!("L2RangeByL1Height", rollback_result);

                batch.delete::<CommitmentsByNumber>(&SlotNumber(i))?;
                increment_table_counter!("CommitmentsByNumber", rollback_result);

                batch.delete::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(i))?;
                increment_table_counter!("VerifiedBatchProofsBySlotNumber", rollback_result);

                if let Some(slot_hash) = l1_cache.get(&i) {
                    batch.delete::<ShortHeaderProofBySlotHash>(slot_hash)?;
                    increment_table_counter!("ShortHeaderProofBySlotHash", rollback_result);
                    batch.delete::<SlotByHash>(slot_hash)?;
                    increment_table_counter!("SlotByHash", rollback_result);
                }
            }

            last_deleted_slot = Some(slot_height.0);
        }

        self.ledger_db.write_schemas(batch)?;
        Ok(rollback_result)
    }

    fn rollback_l2_status_heights(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut batch = SchemaBatch::new();

        let last_scanned_l1_height = self.ledger_db.get::<ProverLastScannedSlot>(&())?;
        let last_scanned_l1_height = last_scanned_l1_height.unwrap_or_default();
        for l1_height in (l1_target..=last_scanned_l1_height.0).rev() {
            batch.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l1_height))?;
            increment_table_counter!("L2StatusHeights", rollback_result);

            batch.delete::<L2StatusHeights>(&(L2HeightStatus::Proven, l1_height))?;
            increment_table_counter!("L2StatusHeights", rollback_result);
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

    fn clear_pending_proofs(&self, l1_target: u64, mut rollback_result: RollbackResult) -> Result {
        let mut batch = SchemaBatch::new();

        // ledger_db.drop_cf requires a mutable ref to DB so we just iterate.
        let mut pending_proofs = self
            .ledger_db
            .iter_with_direction::<PendingProofs>(Default::default(), ScanDirection::Backward)?;
        pending_proofs.seek_to_last();

        for pending_proof in pending_proofs {
            let pending_proof = pending_proof?;
            let (_, proof_l1_height) = pending_proof.value;

            if proof_l1_height <= l1_target {
                continue;
            }

            batch.delete::<PendingProofs>(&pending_proof.key)?;
            increment_table_counter!("PendingProofs", rollback_result);
        }

        self.ledger_db.write_schemas(batch)?;

        Ok(rollback_result)
    }

    fn clear_pending_sequencer_commitments(
        &self,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut batch = SchemaBatch::new();

        let mut pending_sequencer_commitments = self
            .ledger_db
            .iter_with_direction::<PendingSequencerCommitments>(
                Default::default(),
                ScanDirection::Backward,
            )?;
        pending_sequencer_commitments.seek_to_last();

        for sequencer_commitment in pending_sequencer_commitments {
            let sequencer_commitment = sequencer_commitment?;
            let (_, commitment_l1_height) = sequencer_commitment.value;
            if commitment_l1_height <= l1_target {
                continue;
            }
            batch.delete::<PendingSequencerCommitments>(&sequencer_commitment.key)?;

            increment_table_counter!("PendingSequencerCommitments", rollback_result);
        }

        self.ledger_db.write_schemas(batch)?;
        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for FullNodeLedgerRollback {
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
            rollback_result = self.rollback_l2_status_heights(l1_target, rollback_result)?;
            rollback_result = self.clear_pending_proofs(l1_target, rollback_result)?;
            rollback_result =
                self.clear_pending_sequencer_commitments(l1_target, rollback_result)?;

            let _ = self
                .ledger_db
                .put::<ProverLastScannedSlot>(&(), &SlotNumber(l1_target));
        }
        let _ = self.ledger_db.flush();
        Ok(rollback_result)
    }
}
