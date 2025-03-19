use sov_db::schema::tables::SoftConfirmationByNumber;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_soft_confirmations_by_number;

pub(crate) fn prune_soft_confirmations(
    node_type: StorageNodeType,
    ledger_db: &DB,
    up_to_block: u64,
) -> anyhow::Result<u64> {
    let mut soft_confirmations = ledger_db.iter_with_direction::<SoftConfirmationByNumber>(
        Default::default(),
        ScanDirection::Forward,
    )?;
    soft_confirmations.seek_to_first();

    let mut deleted = 0;
    for record in soft_confirmations {
        let Ok(record) = record else {
            continue;
        };

        let soft_confirmation_number = record.key;

        if soft_confirmation_number > SoftConfirmationNumber(up_to_block) {
            break;
        }

        delete_soft_confirmations_by_number(
            node_type,
            ledger_db,
            soft_confirmation_number,
            record.value.hash,
        )?;

        deleted += 1;
    }

    Ok(deleted)
}
