use std::collections::{HashMap, HashSet};

use borsh::de::BorshDeserialize;
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_rollup_interface::da::{BlobReaderTrait, DaDataBatchProof, DaSpec, SequencerCommitment};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateDiff;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map = HashMap::<Vec<u8>, Option<Vec<u8>>>::from_iter(old_diff);

    new_diff_map.extend(new_diff);
    new_diff_map.into_iter().collect()
}

/// Remove proven commitments using the end block number of the L2 range.
/// This is basically filtering out proven soft confirmations.
pub fn filter_out_proven_commitments<DB: SharedLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
    filter_out_commitments_by_status(
        ledger_db,
        sequencer_commitments,
        SoftConfirmationStatus::Proven,
    )
}

fn filter_out_commitments_by_status<DB: SharedLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
    exclude_status: SoftConfirmationStatus,
) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
    let mut skipped_commitments = vec![];
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

        if status != exclude_status {
            filtered.push(sequencer_commitment.clone());
        } else {
            skipped_commitments.push(index);
        }
    }

    Ok((filtered, skipped_commitments))
}

pub fn check_l2_range_exists<DB: SharedLedgerOps>(
    ledger_db: &DB,
    first_l2_height_of_l1: u64,
    last_l2_height_of_l1: u64,
) -> bool {
    if let Ok(range) = ledger_db.get_soft_confirmation_range(
        &(BatchNumber(first_l2_height_of_l1)..=BatchNumber(last_l2_height_of_l1)),
    ) {
        if (range.len() as u64) >= (last_l2_height_of_l1 - first_l2_height_of_l1 + 1) {
            return true;
        }
    }
    false
}

pub fn extract_sequencer_commitments<Da: DaService>(
    sequencer_da_pub_key: &[u8],
    da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
) -> Vec<SequencerCommitment> {
    let mut sequencer_commitments = vec![];
    // if we don't do this, the zk circuit can't read the sequencer commitments
    da_data.iter_mut().for_each(|blob| {
        blob.full_data();
    });
    da_data.iter_mut().for_each(|tx| {
        let data = DaDataBatchProof::try_from_slice(tx.full_data());
        // Check for commitment
        if tx.sender().as_ref() == sequencer_da_pub_key {
            if let Ok(DaDataBatchProof::SequencerCommitment(seq_com)) = data {
                sequencer_commitments.push(seq_com);
            }
        }
    });
    sequencer_commitments
}
