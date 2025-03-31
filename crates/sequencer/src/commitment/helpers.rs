use sov_db::ledger_db::SequencerLedgerOps;

pub(super) fn load_next_commitment_index<Db: SequencerLedgerOps>(db: &Db) -> u32 {
    // max index from pending:
    let max_pending = db
        .get_pending_commitments()
        .unwrap()
        .into_iter()
        .map(|s| s.index)
        .max();
    // max index from last commitment:
    let max_last = db.get_last_commitment().unwrap().map(|s| s.index);
    // maximum of pending and last:
    let max_db = max_pending.max(max_last);
    if let Some(max_db) = max_db {
        max_db + 1
    } else {
        // if comms are empty, then index is 1
        1
    }
}
