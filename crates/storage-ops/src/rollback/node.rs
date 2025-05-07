use std::sync::Arc;

use sov_db::schema::tables::{
    JobIdOfCommitment, L2BlockByHash, L2StatusHeights, ProverLastScannedSlot,
    ProverPendingCommitments, ProverStateDiffs,
};
use sov_db::schema::types::{L2HeightStatus, SlotNumber};
use sov_schema_db::DB;
use tracing::{debug, error};

use super::ledger::commitments::rollback_commitments;
use super::ledger::l2_blocks::rollback_l2_blocks;
use super::ledger::slots::{
    rollback_batch_prover_slots, rollback_light_client_slots, rollback_slot_by_hash,
    rollback_slots, rollback_verified_proofs_by_slot_number,
};
use crate::log_result_or_error;
use crate::types::StorageNodeType;

pub(crate) fn rollback_sequencer(
    ledger_db: Arc<sov_schema_db::DB>,
    target_l2: u64,
    target_l1: u64,
    last_sequencer_commitment_index: u32,
) {
    log_result_or_error!(
        "l2_blocks",
        rollback_l2_blocks(
            &ledger_db,
            target_l2,
            move |ledger_db, _l2_block_number, l2_block_hash| {
                ledger_db.delete::<L2BlockByHash>(&l2_block_hash)?;

                Ok(())
            }
        )
    );
    log_result_or_error!(
        "commitments",
        rollback_commitments(&ledger_db, last_sequencer_commitment_index, move |_, _| {
            Ok(())
        })
    );

    log_result_or_error!(
        "slots",
        rollback_slots(
            StorageNodeType::Sequencer,
            &ledger_db,
            target_l1,
            move |_, _| { Ok(()) }
        )
    );
    let _ = ledger_db.put::<ProverLastScannedSlot>(&(), &SlotNumber(target_l1));
    let _ = ledger_db.flush();
}

pub(crate) fn rollback_fullnode(
    ledger_db: Arc<sov_schema_db::DB>,
    target_l2: u64,
    target_l1: u64,
    last_sequencer_commitment_index: u32,
) {
    log_result_or_error!(
        "l2_blocks",
        rollback_l2_blocks(
            &ledger_db,
            target_l2,
            move |ledger_db, l2_block_number, l2_block_hash| {
                ledger_db.delete::<L2BlockByHash>(&l2_block_hash)?;
                ledger_db
                    .delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l2_block_number.0))?;
                Ok(())
            }
        )
    );
    log_result_or_error!(
        "commitments",
        rollback_commitments(&ledger_db, last_sequencer_commitment_index, move |_, _| {
            Ok(())
        })
    );
    log_result_or_error!(
        "slots",
        rollback_slots(
            StorageNodeType::FullNode,
            &ledger_db,
            target_l1,
            move |ledger_db, slot_height| {
                rollback_slot_by_hash(StorageNodeType::FullNode, ledger_db, slot_height)?;
                rollback_verified_proofs_by_slot_number(ledger_db, slot_height)?;

                Ok(())
            }
        )
    );

    let Ok(last_scanned_l1_height) = ledger_db.get::<ProverLastScannedSlot>(&()) else {
        debug!("Could not get last scanned L1 height");
        return;
    };
    let last_scanned_l1_height = last_scanned_l1_height.unwrap_or_default();
    for l1_height in (target_l1..=last_scanned_l1_height.0).rev() {
        if let Err(e) = ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l1_height))
        {
            error!(
                "Could not delete committed L2StatusHeight at {}: {:?}",
                l1_height, e
            );
        }
        if let Err(e) = ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Proven, l1_height)) {
            error!(
                "Could not delete proven L2StatusHeight at {}: {:?}",
                l1_height, e
            );
        }
    }

    let _ = ledger_db.put::<ProverLastScannedSlot>(&(), &SlotNumber(target_l1));
    let _ = ledger_db.flush();
}

pub(crate) fn rollback_batch_prover(
    ledger_db: Arc<sov_schema_db::DB>,
    target_l2: u64,
    target_l1: u64,
    last_sequencer_commitment_index: u32,
) {
    log_result_or_error!(
        "l2_blocks",
        rollback_l2_blocks(
            &ledger_db,
            target_l2,
            move |ledger_db, l2_block_number, l2_block_hash| {
                ledger_db.delete::<L2BlockByHash>(&l2_block_hash)?;
                ledger_db.delete::<ProverStateDiffs>(&l2_block_number)?;
                Ok(())
            }
        )
    );
    log_result_or_error!(
        "commitments",
        rollback_commitments(
            &ledger_db,
            last_sequencer_commitment_index,
            move |ledger_db: &DB, comm_idx| {
                ledger_db.delete::<JobIdOfCommitment>(&comm_idx)?;
                ledger_db.delete::<ProverPendingCommitments>(&comm_idx)?;

                Ok(())
            }
        )
    );
    log_result_or_error!(
        "slots",
        rollback_batch_prover_slots(StorageNodeType::BatchProver, &ledger_db, target_l1)
    );
    let _ = ledger_db.put::<ProverLastScannedSlot>(&(), &SlotNumber(target_l1));
    let _ = ledger_db.flush();
}

pub(crate) fn rollback_light_client(
    ledger_db: Arc<sov_schema_db::DB>,
    target_l2: u64,
    target_l1: u64,
) {
    log_result_or_error!(
        "l2_blocks",
        rollback_l2_blocks(
            &ledger_db,
            target_l2,
            move |_ledger_db, _l2_block_number, _l2_block_hash| { Ok(()) }
        )
    );
    log_result_or_error!("slots", rollback_light_client_slots(&ledger_db, target_l1));
    let _ = ledger_db.put::<ProverLastScannedSlot>(&(), &SlotNumber(target_l1));
    let _ = ledger_db.flush();
}
