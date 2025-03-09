use sov_db::schema::tables::{LastSequencerCommitmentSent, SoftConfirmationByNumber};
use sov_db::schema::types::SoftConfirmationNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_soft_confirmations_by_number;

pub(crate) fn rollback_soft_confirmations(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l2: u64,
    last_sequencer_commitment_l2_height: u64,
) -> anyhow::Result<u64> {
    let mut soft_confirmations = ledger_db.iter_with_direction::<SoftConfirmationByNumber>(
        Default::default(),
        ScanDirection::Backward,
    )?;
    soft_confirmations.seek_to_last();

    let mut deleted = 0;
    for record in soft_confirmations {
        let Ok(record) = record else {
            continue;
        };

        let soft_confirmation_number = record.key;

        if soft_confirmation_number <= SoftConfirmationNumber(target_l2) {
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

    if matches!(node_type, StorageNodeType::Sequencer)
        || matches!(node_type, StorageNodeType::FullNode)
    {
        ledger_db.put::<LastSequencerCommitmentSent>(
            &(),
            &SoftConfirmationNumber(last_sequencer_commitment_l2_height),
        )?;
    }

    Ok(deleted)
}
