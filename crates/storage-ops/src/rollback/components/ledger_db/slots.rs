use sov_db::schema::tables::{L2RangeByL1Height, LastSequencerCommitmentSent};
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_slots_by_number;

pub(crate) fn rollback_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l1: u64,
) -> anyhow::Result<u64> {
    let mut slots_to_l2_range = ledger_db
        .iter_with_direction::<L2RangeByL1Height>(Default::default(), ScanDirection::Backward)?;
    slots_to_l2_range.seek_to_last();

    let mut deleted = 0;
    for record in slots_to_l2_range {
        let Ok(record) = record else {
            continue;
        };

        let slot_height = record.key;

        if slot_height <= SlotNumber(target_l1) {
            break;
        }

        if matches!(node_type, StorageNodeType::Sequencer)
            || matches!(node_type, StorageNodeType::FullNode)
        {
            let slot_range = record.value;
            // TODO: Figure out a way to set it to an actual
            // commitment range L2 end.
            // `CommitmentsByNumber` table is only populated by
            // the batch prover.
            ledger_db.put::<LastSequencerCommitmentSent>(
                &(),
                &SoftConfirmationNumber(slot_range.0 .0 - 1),
            )?;
        }

        delete_slots_by_number(node_type, ledger_db, slot_height)?;

        deleted += 1;
    }

    Ok(deleted)
}
