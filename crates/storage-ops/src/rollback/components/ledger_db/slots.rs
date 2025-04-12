use sov_db::schema::tables::{
    CommitmentIndicesByL1, CommitmentsByNumber, L2StatusHeights, LightClientProofBySlotNumber,
    ProverLastScannedSlot, ShortHeaderProofBySlotHash, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L2HeightStatus, SlotNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_slots_by_number;

pub(crate) fn rollback_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l1: u64,
) -> anyhow::Result<u64> {
    let mut commitments_by_number = ledger_db
        .iter_with_direction::<CommitmentsByNumber>(Default::default(), ScanDirection::Backward)?;
    commitments_by_number.seek_to_last();

    let mut deleted = 0;
    for record in commitments_by_number {
        let Ok(record) = record else {
            continue;
        };

        let slot_height = record.key;

        if slot_height <= SlotNumber(target_l1) {
            break;
        }

        delete_slots_by_number(node_type, ledger_db, slot_height)?;

        if !matches!(node_type, StorageNodeType::Sequencer) {
            rollback_slot_by_hash(node_type, ledger_db, slot_height)?;
        }

        if matches!(node_type, StorageNodeType::FullNode) {
            rollback_verified_proofs_by_slot_number(ledger_db, slot_height)?;
        }

        deleted += 1;
    }

    if matches!(node_type, StorageNodeType::FullNode) {
        let last_scanned_l1_height = ledger_db
            .get::<ProverLastScannedSlot>(&())?
            .unwrap_or_default();
        for l1_height in (target_l1..=last_scanned_l1_height.0).rev() {
            ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l1_height))?;
            ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Proven, l1_height))?;
        }
    }

    Ok(deleted)
}

// CommitmentIndicesByL1
// JobIdOfCommitment
pub(crate) fn rollback_batch_prover_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l1: u64,
) -> anyhow::Result<u64> {
    // target_l1 + 1 due to rollback_slot_by_hash being inclusive
    let deleted = rollback_slot_by_hash(node_type, ledger_db, SlotNumber(target_l1 + 1))?;

    let mut commitment_indices_by_l1 = ledger_db.iter_with_direction::<CommitmentIndicesByL1>(
        Default::default(),
        ScanDirection::Backward,
    )?;
    commitment_indices_by_l1.seek_to_last();

    for record in commitment_indices_by_l1 {
        let l1_height = record?.key;

        if l1_height <= SlotNumber(target_l1) {
            break;
        }

        ledger_db.delete::<CommitmentIndicesByL1>(&l1_height)?;
    }

    Ok(deleted)
}

pub(crate) fn rollback_light_client_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l1: u64,
) -> anyhow::Result<u64> {
    let mut proof_by_slot_number = ledger_db.iter_with_direction::<LightClientProofBySlotNumber>(
        Default::default(),
        ScanDirection::Backward,
    )?;
    proof_by_slot_number.seek_to_last();

    let mut deleted = 0;
    for record in proof_by_slot_number {
        let Ok(record) = record else {
            continue;
        };

        let slot_height = record.key;

        if slot_height <= SlotNumber(target_l1) {
            break;
        }

        delete_slots_by_number(node_type, ledger_db, slot_height)?;

        deleted += 1;
    }

    Ok(deleted)
}

fn rollback_slot_by_hash(
    node_type: StorageNodeType,
    ledger_db: &DB,
    slot_number: SlotNumber,
) -> anyhow::Result<u64> {
    let mut slots =
        ledger_db.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Backward)?;
    slots.seek_to_last();

    let mut deleted = 0;
    for record in slots {
        let Ok(record) = record else {
            continue;
        };

        if record.value < slot_number {
            break;
        }

        if !matches!(node_type, StorageNodeType::LightClient) {
            ledger_db.delete::<ShortHeaderProofBySlotHash>(&record.key)?;
        }

        ledger_db.delete::<SlotByHash>(&record.key)?;

        deleted += 1;
    }

    Ok(deleted)
}

fn rollback_verified_proofs_by_slot_number(
    ledger_db: &DB,
    slot_number: SlotNumber,
) -> anyhow::Result<()> {
    let mut verified_proofs_by_number = ledger_db
        .iter_with_direction::<VerifiedBatchProofsBySlotNumber>(
            Default::default(),
            ScanDirection::Backward,
        )?;
    verified_proofs_by_number.seek_to_last();

    for record in verified_proofs_by_number {
        let Ok(record) = record else {
            continue;
        };

        if record.key < slot_number {
            break;
        }

        ledger_db.delete::<VerifiedBatchProofsBySlotNumber>(&record.key)?;
    }

    Ok(())
}
