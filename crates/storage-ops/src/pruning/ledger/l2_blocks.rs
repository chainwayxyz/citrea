use citrea_common::NodeType;
use sov_db::schema::tables::{L2BlockByHash, L2BlockByNumber, L2StatusHeights, ProverStateDiffs};
use sov_db::schema::types::{L2BlockNumber, L2HeightStatus};
use sov_schema_db::{ScanDirection, DB};

pub(crate) fn prune_l2_blocks(
    node_type: NodeType,
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

        ledger_db.delete::<L2BlockByNumber>(&l2_block_number)?;

        if matches!(node_type, NodeType::LightClientProver) {
            return Ok(deleted);
        }

        ledger_db.delete::<L2BlockByHash>(&record.value.hash)?;

        if matches!(node_type, NodeType::BatchProver) {
            ledger_db.delete::<ProverStateDiffs>(&l2_block_number)?;
        }

        if matches!(node_type, NodeType::FullNode) {
            ledger_db.delete::<L2StatusHeights>(&(L2HeightStatus::Committed, l2_block_number.0))?;
        }

        deleted += 1;
    }

    Ok(deleted)
}
