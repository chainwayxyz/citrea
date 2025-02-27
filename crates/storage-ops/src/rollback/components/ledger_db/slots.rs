use sov_db::schema::tables::CommitmentsByNumber;
use sov_db::schema::types::SlotNumber;
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

        deleted += 1;
    }

    Ok(deleted)
}
