use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, LightClientProofBySlotNumber, ProofsBySlotNumber,
    ProofsBySlotNumberV2, ShortHeaderProofBySlotHash, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::types::StorageNodeType;

pub(crate) fn prune_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    up_to_block: u64,
) -> anyhow::Result<u64> {
    let mut slots_to_l2_range = ledger_db
        .iter_with_direction::<L2RangeByL1Height>(Default::default(), ScanDirection::Forward)?;
    slots_to_l2_range.seek_to_first();

    let mut deleted = 0;
    for record in slots_to_l2_range {
        let Ok(record) = record else {
            continue;
        };

        let slot_height = record.key;
        let slot_range = record.value;

        if slot_range.1 > L2BlockNumber(up_to_block) {
            break;
        }

        ledger_db.delete::<L2RangeByL1Height>(&slot_height)?;
        ledger_db.delete::<CommitmentsByNumber>(&slot_height)?;

        if matches!(node_type, StorageNodeType::BatchProver) {
            ledger_db.delete::<ProofsBySlotNumber>(&slot_height)?;
            ledger_db.delete::<ProofsBySlotNumberV2>(&slot_height)?;
        }

        if matches!(node_type, StorageNodeType::LightClient) {
            ledger_db.delete::<LightClientProofBySlotNumber>(&slot_height)?;
        }

        if !matches!(node_type, StorageNodeType::Sequencer) {
            prune_slot_by_hash(node_type, ledger_db, slot_height)?;
        }

        if matches!(node_type, StorageNodeType::FullNode) {
            prune_verified_proofs_by_slot_number(ledger_db, slot_height)?;
        }

        deleted += 1;
    }

    Ok(deleted)
}

fn prune_slot_by_hash(
    node_type: StorageNodeType,
    ledger_db: &DB,
    slot_number: SlotNumber,
) -> anyhow::Result<()> {
    let mut slots =
        ledger_db.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Forward)?;
    slots.seek_to_first();

    for record in slots {
        let Ok(record) = record else {
            continue;
        };

        if record.value > slot_number {
            break;
        }

        if !matches!(node_type, StorageNodeType::LightClient) {
            ledger_db.delete::<ShortHeaderProofBySlotHash>(&record.key)?;
        }

        ledger_db.delete::<SlotByHash>(&record.key)?;
    }

    Ok(())
}

fn prune_verified_proofs_by_slot_number(
    ledger_db: &DB,
    slot_number: SlotNumber,
) -> anyhow::Result<()> {
    let mut verified_proofs_by_number = ledger_db
        .iter_with_direction::<VerifiedBatchProofsBySlotNumber>(
            Default::default(),
            ScanDirection::Forward,
        )?;
    verified_proofs_by_number.seek_to_first();

    for record in verified_proofs_by_number {
        let Ok(record) = record else {
            continue;
        };

        if record.key > slot_number {
            break;
        }

        ledger_db.delete::<VerifiedBatchProofsBySlotNumber>(&record.key)?;
    }

    Ok(())
}
