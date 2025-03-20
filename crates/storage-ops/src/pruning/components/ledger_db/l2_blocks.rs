use sov_db::schema::tables::L2BlockByNumber;
use sov_db::schema::types::L2BlockNumber;
use sov_schema_db::{ScanDirection, DB};

use crate::pruning::types::StorageNodeType;
use crate::utils::delete_l2_blocks_by_number;

pub(crate) fn prune_l2_blocks(
    node_type: StorageNodeType,
    ledger_db: &DB,
    up_to_block: u64,
) -> anyhow::Result<u64> {
    let mut l2_blocks = ledger_db
        .iter_with_direction::<L2BlockByNumber>(Default::default(), ScanDirection::Forward)?;
    l2_blocks.seek_to_first();

    let mut deleted = 0;
    for record in l2_blocks {
        let Ok(record) = record else {
            continue;
        };

        let l2_block_number = record.key;

        if l2_block_number > L2BlockNumber(up_to_block) {
            break;
        }

        delete_l2_blocks_by_number(node_type, ledger_db, l2_block_number, record.value.hash)?;

        deleted += 1;
    }

    Ok(deleted)
}
