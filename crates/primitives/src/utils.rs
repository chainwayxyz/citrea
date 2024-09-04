use std::collections::{HashMap, HashSet};

use sov_db::ledger_db::SharedLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::stf::StateDiff;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map = HashMap::<Vec<u8>, Option<Vec<u8>>>::from_iter(old_diff);

    new_diff_map.extend(new_diff);
    new_diff_map.into_iter().collect()
}

/// Remove proven commitments using the end block number of the L2 range.
/// This is basically filtering out finalized soft confirmations.
pub fn filter_out_proven_commitments<DB: SharedLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
    let mut preproven_commitments = vec![];
    let mut filtered = vec![];
    let mut visited_l2_ranges = HashSet::new();
    for (index, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        // Handle commitments which have the same L2 range
        let current_range = (
            sequencer_commitment.l2_start_block_number,
            sequencer_commitment.l2_end_block_number,
        );
        if visited_l2_ranges.contains(&current_range) {
            continue;
        }
        visited_l2_ranges.insert(current_range);

        // Check if the commitment was previously finalized.
        let Some(status) = ledger_db
            .get_soft_confirmation_status(BatchNumber(sequencer_commitment.l2_end_block_number))?
        else {
            filtered.push(sequencer_commitment.clone());
            continue;
        };

        if status != SoftConfirmationStatus::Finalized {
            filtered.push(sequencer_commitment.clone());
        } else {
            preproven_commitments.push(index);
        }
    }

    Ok((filtered, preproven_commitments))
}
