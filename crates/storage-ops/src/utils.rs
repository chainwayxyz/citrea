use sov_db::schema::tables::{
    CommitmentsByNumber, L2BlockByHash, L2BlockByNumber, L2RangeByL1Height, L2StatusHeights,
    LightClientProofBySlotNumber, ProofsBySlotNumber, ProofsBySlotNumberV2, ProverStateDiffs,
};
use sov_db::schema::types::{DbHash, L2BlockNumber, L2HeightStatus, SlotNumber};
use sov_schema_db::DB;

use crate::pruning::types::StorageNodeType;

pub(crate) fn delete_l2_blocks_by_number(
    node_type: StorageNodeType,
    ledger_db: &DB,
    l2_block_number: L2BlockNumber,
    l2_block_hash: DbHash,
) -> anyhow::Result<()> {
    ledger_db.delete::<L2BlockByNumber>(&l2_block_number)?;

    if matches!(node_type, StorageNodeType::LightClient) {
        return Ok(());
    }

    ledger_db.delete::<L2BlockByHash>(&l2_block_hash)?;

    if matches!(node_type, StorageNodeType::BatchProver) {
        ledger_db.delete::<ProverStateDiffs>(&l2_block_number)?;
    }

    if matches!(node_type, StorageNodeType::FullNode) {
        ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l2_block_number.0))?;
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
