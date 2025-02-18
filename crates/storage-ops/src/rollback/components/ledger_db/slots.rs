use sov_db::schema::tables::L2RangeByL1Height;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_slots_by_number;

pub(crate) fn rollback_slots(
    node_type: StorageNodeType,
    ledger_db: &DB,
    down_to_block: u64,
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
        let slot_range = record.value;

        if slot_range.0 < SoftConfirmationNumber(down_to_block) {
            break;
        }

        delete_slots_by_number(node_type, ledger_db, slot_height)?;

        deleted += 1;
    }

    Ok(deleted)
}
