use sov_db::schema::tables::{
    L2Witness, ProverStateDiffs, SoftConfirmationByHash, SoftConfirmationByNumber,
    SoftConfirmationStatus,
};
use sov_db::schema::types::SoftConfirmationNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::PruningNodeType;

pub(crate) fn prune_soft_confirmations(
    node_type: PruningNodeType,
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
        ledger_db.delete::<SoftConfirmationByNumber>(&soft_confirmation_number)?;

        if matches!(node_type, PruningNodeType::LightClient) {
            continue;
        }

        let soft_confirmation = record.value;
        ledger_db.delete::<SoftConfirmationByHash>(&soft_confirmation.hash)?;
        ledger_db.delete::<SoftConfirmationStatus>(&soft_confirmation_number)?;

        if matches!(node_type, PruningNodeType::BatchProver) {
            ledger_db.delete::<L2Witness>(&soft_confirmation_number)?;
            ledger_db.delete::<ProverStateDiffs>(&soft_confirmation_number)?;
        }

        deleted += 1;
    }

    Ok(deleted)
}
