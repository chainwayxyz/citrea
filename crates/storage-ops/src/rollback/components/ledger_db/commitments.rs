use sov_db::schema::tables::SequencerCommitmentByIndex;
use sov_schema_db::{ScanDirection, DB};

pub(crate) fn rollback_commitments<F>(
    ledger_db: &DB,
    last_sequencer_commitment_index: u32,
    callback: F,
) -> anyhow::Result<u64>
where
    F: Fn(&DB, u32) -> anyhow::Result<()> + Clone,
{
    let mut deleted = 0;
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

        callback(ledger_db, comm_idx)?;

        deleted += 1;
    }

    Ok(deleted)
}
