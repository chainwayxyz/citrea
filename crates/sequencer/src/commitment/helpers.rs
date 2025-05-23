use sov_db::ledger_db::SequencerLedgerOps;

pub(super) fn load_next_commitment_index_and_start_height<Db: SequencerLedgerOps>(
    db: &Db,
) -> (u32, u64) {
    let pending_commitments = db
        .get_pending_commitments()
        .expect("Failed to get pending commitments");
    let last_commitment = db
        .get_last_commitment()
        .expect("Failed to get last commitment");

    let max_commitment = pending_commitments
        .into_iter()
        .map(Some)
        .chain(std::iter::once(last_commitment))
        .flatten()
        .max();

    match max_commitment {
        Some(commitment) => (commitment.index + 1, commitment.l2_end_block_number + 1),
        // TODO: should this be tangerine start height?
        None => (1, 1),
    }
}
