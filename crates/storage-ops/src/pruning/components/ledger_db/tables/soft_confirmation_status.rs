use sov_db::schema::tables::SoftConfirmationStatus;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_schema_db::{ScanDirection, DB};

pub(crate) fn prune_soft_confirmation_status(
    ledger_db: &DB,
    up_to_block: u64,
) -> anyhow::Result<u64> {
    let soft_confirmation_status = ledger_db.iter_with_direction::<SoftConfirmationStatus>(
        Default::default(),
        ScanDirection::Forward,
    )?;

    let mut deleted = 0;
    for record in soft_confirmation_status {
        let Ok(record) = record else {
            continue;
        };

        let soft_confirmation_number = record.key;

        if soft_confirmation_number > SoftConfirmationNumber(up_to_block) {
            break;
        }
        ledger_db.delete::<SoftConfirmationStatus>(&record.key)?;
        deleted += 1;
    }

    Ok(deleted)
}
