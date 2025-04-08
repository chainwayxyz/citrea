use sov_db::schema::tables::{
    JobIdOfCommitment, L2BlockByNumber, ProverPendingCommitments, SequencerCommitmentByIndex,
};
use sov_db::schema::types::L2BlockNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_l2_blocks_by_number;

pub(crate) fn rollback_l2_blocks(
    node_type: StorageNodeType,
    ledger_db: &DB,
    target_l2: u64,
    last_sequencer_commitment_index: u32,
) -> anyhow::Result<u64> {
    let mut l2_blocks = ledger_db
        .iter_with_direction::<L2BlockByNumber>(Default::default(), ScanDirection::Backward)?;
    l2_blocks.seek_to_last();

    let mut deleted = 0;
    for record in l2_blocks {
        let record = record?;
        let l2_block_number = record.key;

        if l2_block_number <= L2BlockNumber(target_l2) {
            break;
        }

        delete_l2_blocks_by_number(node_type, ledger_db, l2_block_number, record.value.hash)?;

        deleted += 1;
    }

    if matches!(node_type, StorageNodeType::LightClient) {
        return Ok(deleted);
    }

    let mut comm_iter = ledger_db.iter_with_direction::<SequencerCommitmentByIndex>(
        Default::default(),
        ScanDirection::Backward,
    )?;
    comm_iter.seek_to_last();

    for record in comm_iter {
        let comm_idx = record?.key;
        if comm_idx <= last_sequencer_commitment_index {
            break;
        }

        ledger_db.delete::<SequencerCommitmentByIndex>(&comm_idx)?;

        if matches!(node_type, StorageNodeType::BatchProver) {
            ledger_db.delete::<JobIdOfCommitment>(&comm_idx)?;
            ledger_db.delete::<ProverPendingCommitments>(&comm_idx)?;
        }
    }

    Ok(deleted)
}
