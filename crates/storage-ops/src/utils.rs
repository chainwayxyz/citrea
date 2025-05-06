use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, LightClientProofBySlotNumber, ProofsBySlotNumber,
    ProofsBySlotNumberV2,
};
use sov_db::schema::types::SlotNumber;
use sov_schema_db::DB;

use crate::types::StorageNodeType;

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
