use citrea_common::utils::shutdown_requested;
use citrea_common::NodeType;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, LightClientProofBySlotNumber, ProofsBySlotNumber,
    ProofsBySlotNumberV2, ShortHeaderProofBySlotHash, SlotByHash, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::{L1BlockNumber, L2BlockNumber};
use sov_schema_db::{ScanDirection, SchemaBatch, DB};

pub(crate) fn prune_slots(
    node_type: NodeType,
    ledger_db: &DB,
    up_to_block: u64,
    shutdown_signal: Option<&GracefulShutdown>,
) -> anyhow::Result<u64> {
    let mut slots_to_l2_range = ledger_db
        .iter_with_direction::<L2RangeByL1Height>(Default::default(), ScanDirection::Forward)?;
    slots_to_l2_range.seek_to_first();

    let mut batch = SchemaBatch::new();
    let mut deleted = 0;
    for record in slots_to_l2_range {
        if shutdown_signal.is_some_and(shutdown_requested) {
            anyhow::bail!("Shutting down pruner");
        }

        let Ok(record) = record else {
            continue;
        };

        let slot_height = record.key;
        let slot_range = record.value;

        if slot_range.1 > L2BlockNumber(up_to_block) {
            break;
        }

        batch.delete::<L2RangeByL1Height>(&slot_height)?;
        batch.delete::<CommitmentsByNumber>(&slot_height)?;

        if matches!(node_type, NodeType::BatchProver) {
            batch.delete::<ProofsBySlotNumber>(&slot_height)?;
            batch.delete::<ProofsBySlotNumberV2>(&slot_height)?;
        }

        if matches!(node_type, NodeType::LightClientProver) {
            batch.delete::<LightClientProofBySlotNumber>(&slot_height)?;
        }

        if !matches!(node_type, NodeType::Sequencer) {
            prune_slot_by_hash(
                node_type,
                ledger_db,
                slot_height,
                &mut batch,
                shutdown_signal,
            )?;
        }

        if matches!(node_type, NodeType::FullNode) {
            prune_verified_proofs_by_slot_number(
                ledger_db,
                slot_height,
                &mut batch,
                shutdown_signal,
            )?;
        }

        deleted += 1;
    }

    ledger_db.write_schemas(batch)?;

    Ok(deleted)
}

fn prune_slot_by_hash(
    node_type: NodeType,
    ledger_db: &DB,
    slot_number: L1BlockNumber,
    batch: &mut SchemaBatch,
    shutdown_signal: Option<&GracefulShutdown>,
) -> anyhow::Result<()> {
    let mut slots =
        ledger_db.iter_with_direction::<SlotByHash>(Default::default(), ScanDirection::Forward)?;
    slots.seek_to_first();

    for record in slots {
        if shutdown_signal.is_some_and(shutdown_requested) {
            anyhow::bail!("Shutting down pruner");
        }

        let Ok(record) = record else {
            continue;
        };

        if record.value > slot_number {
            break;
        }

        if !matches!(node_type, NodeType::LightClientProver) {
            batch.delete::<ShortHeaderProofBySlotHash>(&record.key)?;
        }

        batch.delete::<SlotByHash>(&record.key)?;
    }

    Ok(())
}

fn prune_verified_proofs_by_slot_number(
    ledger_db: &DB,
    slot_number: L1BlockNumber,
    batch: &mut SchemaBatch,
    shutdown_signal: Option<&GracefulShutdown>,
) -> anyhow::Result<()> {
    let mut verified_proofs_by_number = ledger_db
        .iter_with_direction::<VerifiedBatchProofsBySlotNumber>(
            Default::default(),
            ScanDirection::Forward,
        )?;
    verified_proofs_by_number.seek_to_first();

    for record in verified_proofs_by_number {
        if shutdown_signal.is_some_and(shutdown_requested) {
            anyhow::bail!("Shutting down pruner");
        }

        let Ok(record) = record else {
            continue;
        };

        if record.key > slot_number {
            break;
        }

        batch.delete::<VerifiedBatchProofsBySlotNumber>(&record.key)?;
    }

    Ok(())
}
