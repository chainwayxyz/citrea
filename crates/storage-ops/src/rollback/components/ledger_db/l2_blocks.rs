use sov_db::schema::tables::L2BlockByNumber;
use sov_db::schema::types::{DbHash, L2BlockNumber};
use sov_schema_db::{ScanDirection, DB};

pub(crate) fn rollback_l2_blocks<F>(
    ledger_db: &DB,
    target_l2: u64,
    callback: F,
) -> anyhow::Result<u64>
where
    F: Fn(&DB, L2BlockNumber, DbHash) -> anyhow::Result<()>,
{
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

        ledger_db.delete::<L2BlockByNumber>(&l2_block_number)?;

        callback(ledger_db, l2_block_number, record.value.hash)?;

        deleted += 1;
    }

    Ok(deleted)
}
