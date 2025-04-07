use sov_db::schema::tables::{
    CommitmentsByNumber, L2StatusHeights, LightClientProofBySlotNumber, ShortHeaderProofBySlotHash,
    SlotByHash, VerifiedBatchProofsBySlotNumber,
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
) -> anyhow::Result<()> {
    let mut slots =
        ledger_db.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Backward)?;
    slots.seek_to_last();

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
    }

    Ok(())
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

        let proofs = record.value;
        for proof in proofs.into_iter().rev() {
            let output = proof.proof_output;
            ledger_db
                .delete::<L2StatusHeights>(&(L2HeightStatus::Proven, output.last_l2_height()))?;
        }
    }

    Ok(())
}
