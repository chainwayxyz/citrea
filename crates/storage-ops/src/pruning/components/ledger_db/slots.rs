use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, LightClientProofBySlotNumber, ProofsBySlotNumber,
    ProofsBySlotNumberV2, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::PruningNodeType;

pub(crate) fn prune_slots(
    node_type: PruningNodeType,
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

        if slot_range.1 > SoftConfirmationNumber(up_to_block) {
            break;
        }
        ledger_db.delete::<L2RangeByL1Height>(&slot_height)?;
        ledger_db.delete::<CommitmentsByNumber>(&slot_height)?;

        if !matches!(node_type, PruningNodeType::Sequencer) {
            prune_slot_by_hash(ledger_db, slot_height)?;
        }

        if matches!(node_type, PruningNodeType::FullNode) {
            ledger_db.delete::<VerifiedBatchProofsBySlotNumber>(&slot_height)?;
        }

        if matches!(node_type, PruningNodeType::BatchProver) {
            ledger_db.delete::<ProofsBySlotNumber>(&slot_height)?;
            ledger_db.delete::<ProofsBySlotNumberV2>(&slot_height)?;
        }

        if matches!(node_type, PruningNodeType::LightClient) {
            ledger_db.delete::<LightClientProofBySlotNumber>(&slot_height)?;
        }

        deleted += 1;
    }

    Ok(deleted)
}

fn prune_slot_by_hash(ledger_db: &DB, slot_height: SlotNumber) -> anyhow::Result<()> {
    let mut slots =
        ledger_db.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Forward)?;
    slots.seek_to_first();

    for record in slots {
        let Ok(record) = record else {
            continue;
        };

        if record.value < slot_height {
            ledger_db.delete::<SlotByHash>(&record.key)?;
        }
    }

    Ok(())
}
