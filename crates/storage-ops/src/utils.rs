use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, L2StatusHeights, L2Witness,
    LightClientProofBySlotNumber, ProofsBySlotNumber, ProofsBySlotNumberV2, ProverStateDiffs,
    SoftConfirmationByHash, SoftConfirmationByNumber, SoftConfirmationStatus,
};
use sov_db::schema::types::{DbHash, L2HeightStatus, SlotNumber, SoftConfirmationNumber};
use sov_schema_db::DB;

use crate::pruning::types::StorageNodeType;

pub(crate) fn delete_soft_confirmations_by_number(
    node_type: StorageNodeType,
    ledger_db: &DB,
    soft_confirmation_number: SoftConfirmationNumber,
    soft_confirmation_hash: DbHash,
) -> anyhow::Result<()> {
    ledger_db.delete::<SoftConfirmationByNumber>(&soft_confirmation_number)?;

    if matches!(node_type, StorageNodeType::LightClient) {
        return Ok(());
    }

    ledger_db.delete::<SoftConfirmationByHash>(&soft_confirmation_hash)?;
    ledger_db.delete::<SoftConfirmationStatus>(&soft_confirmation_number)?;

    if matches!(node_type, StorageNodeType::BatchProver) {
        ledger_db.delete::<L2Witness>(&soft_confirmation_number)?;
        ledger_db.delete::<ProverStateDiffs>(&soft_confirmation_number)?;
    }

    if matches!(node_type, StorageNodeType::FullNode) {
        ledger_db
            .delete::<L2StatusHeights>(&(L2HeightStatus::Committed, soft_confirmation_number.0))?;
    }

    Ok(())
}

pub(crate) fn delete_slots_by_number(
    node_type: StorageNodeType,
    ledger_db: &DB,
    slot_number: SlotNumber,
) -> anyhow::Result<()> {
    ledger_db.delete::<L2RangeByL1Height>(&slot_number)?;
    ledger_db.delete::<CommitmentsByNumber>(&slot_number)?;

    if matches!(node_type, StorageNodeType::BatchProver) {
        ledger_db.delete::<ProofsBySlotNumber>(&slot_number)?;
        ledger_db.delete::<ProofsBySlotNumberV2>(&slot_number)?;
    }

    if matches!(node_type, StorageNodeType::LightClient) {
        ledger_db.delete::<LightClientProofBySlotNumber>(&slot_number)?;
    }

    Ok(())
}
