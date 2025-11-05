use std::collections::HashMap;

use sov_db::ledger_db::{LedgerDBTransaction, TransactionLedgerDB};
use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByHash, L2BlockByNumber, L2RangeByL1Height, L2StatusHeights,
    PendingProofs, PendingSequencerCommitments, ProverLastScannedSlot, SequencerCommitmentByIndex,
    ShortHeaderProofBySlotHash, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L2BlockNumber, L2HeightStatus, SlotNumber};
use sov_schema_db::ScanDirection;

use crate::increment_table_counter;
use crate::rollback::types::{LedgerNodeRollback, Result, RollbackContext, RollbackResult};

pub struct FullNodeLedgerRollback {
    ledger_db: TransactionLedgerDB,
}

impl FullNodeLedgerRollback {
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

            tx.delete::<PendingSequencerCommitments>(&comm_idx)?;
            increment_table_counter!("PendingSequencerCommitments", rollback_result);
        }

        Ok(rollback_result)
    }

    fn rollback_slots(
        tx: &LedgerDBTransaction,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let l1_cache = Self::construct_l1_cache(tx)?;

        let last_scanned_l1_height = tx.get::<ProverLastScannedSlot>(&())?.unwrap_or_default();
        for i in l1_target + 1..=last_scanned_l1_height.0 {
            tx.delete::<L2RangeByL1Height>(&SlotNumber(i))?;
            increment_table_counter!("L2RangeByL1Height", rollback_result);

            tx.delete::<CommitmentsByNumber>(&SlotNumber(i))?;
            increment_table_counter!("CommitmentsByNumber", rollback_result);

            tx.delete::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(i))?;
            increment_table_counter!("VerifiedBatchProofsBySlotNumber", rollback_result);

            tx.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, i))?;
            increment_table_counter!("L2StatusHeights", rollback_result);

            tx.delete::<L2StatusHeights>(&(L2HeightStatus::Proven, i))?;
            increment_table_counter!("L2StatusHeights", rollback_result);

            if let Some(slot_hash) = l1_cache.get(&i) {
                tx.delete::<ShortHeaderProofBySlotHash>(slot_hash)?;
                increment_table_counter!("ShortHeaderProofBySlotHash", rollback_result);
                tx.delete::<SlotByHash>(slot_hash)?;
                increment_table_counter!("SlotByHash", rollback_result);
            }
        }

        Ok(rollback_result)
    }

    fn construct_l1_cache(tx: &LedgerDBTransaction) -> anyhow::Result<HashMap<u64, [u8; 32]>> {
        let mut cache = HashMap::new();
        let mut slots =
            tx.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Forward)?;
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

    fn clear_pending_proofs(
        tx: &LedgerDBTransaction,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        // ledger_db.drop_cf requires a mutable ref to DB so we just iterate.
        let mut pending_proofs =
            tx.iter_with_direction::<PendingProofs>(Default::default(), ScanDirection::Backward)?;
        pending_proofs.seek_to_last();

        for pending_proof in pending_proofs {
            let pending_proof = pending_proof?;
            let (_, proof_l1_height) = pending_proof.value;

            if proof_l1_height <= l1_target {
                continue;
            }

            tx.delete::<PendingProofs>(&pending_proof.key)?;
            increment_table_counter!("PendingProofs", rollback_result);
        }

        Ok(rollback_result)
    }

    fn clear_pending_sequencer_commitments(
        tx: &LedgerDBTransaction,
        l1_target: u64,
        mut rollback_result: RollbackResult,
    ) -> Result {
        let mut pending_sequencer_commitments = tx
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
            tx.delete::<PendingSequencerCommitments>(&sequencer_commitment.key)?;

            increment_table_counter!("PendingSequencerCommitments", rollback_result);
        }

        Ok(rollback_result)
    }
}

impl LedgerNodeRollback for FullNodeLedgerRollback {
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
            rollback_result = Self::clear_pending_proofs(&tx, l1_target, rollback_result)?;
            rollback_result =
                Self::clear_pending_sequencer_commitments(&tx, l1_target, rollback_result)?;

            tx.put::<ProverLastScannedSlot>(&(), &SlotNumber(l1_target))?;
        }
        tx.commit()?;
        Ok(rollback_result)
    }
}
