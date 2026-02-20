use citrea_common::NodeType;
use sov_db::schema::tables::{L2BlockByNumber, ProverStateDiffs};
use sov_db::schema::types::L2BlockNumber;
use sov_schema_db::{ScanDirection, SchemaBatch, DB};

/// Prunes L2 blocks by removing transaction bodies while keeping block headers.
pub(crate) fn prune_l2_blocks(
    node_type: NodeType,
    ledger_db: &DB,
    up_to_block: u64,
) -> anyhow::Result<u64> {
    let mut l2_blocks = ledger_db
        .iter_with_direction::<L2BlockByNumber>(Default::default(), ScanDirection::Forward)?;
    l2_blocks.seek_to_first();

    let mut batch = SchemaBatch::new();
    let mut pruned = 0;
    for record in l2_blocks {
        let Ok(record) = record else {
            continue;
        };

        let l2_block_number = record.key;

        if l2_block_number > L2BlockNumber(up_to_block) {
            break;
        }

        let mut pruned_block = record.value;
        for tx in &mut pruned_block.txs {
            tx.body = None; // Clear tx body
        }

        batch.put::<L2BlockByNumber>(&l2_block_number, &pruned_block)?;

        if matches!(node_type, NodeType::BatchProver) {
            batch.delete::<ProverStateDiffs>(&l2_block_number)?;
        }

        pruned += 1;
    }

    ledger_db.write_schemas(batch)?;

    Ok(pruned)
}
